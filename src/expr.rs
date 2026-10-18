//! Scalar expressions (E55): what a SELECT list, a WHERE condition, an aggregate's argument, a GROUP BY key or an
//! UPDATE's SET computes from one row, beyond a bare column. Planned once into an `SExpr`, bound to the statement's
//! parameters and scalar subqueries per execution, then evaluated over decoded values.
//!
//! Strict like the rest of the engine (E29): division by zero, integer overflow, and comparing or combining values of
//! different types are errors, not NULL or a guess. NULL propagates the SQL way, AND and OR use three-valued logic.
use crate::table::{format_uuid, now_micros, parse_timestamp, parse_uuid, uuid_v4, uuid_v7, ColType, Value};
use std::cmp::Ordering;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op { Add, Sub, Mul, Div, Mod, Concat, Eq, Ne, Lt, Le, Gt, Ge, And, Or, JsonGet, JsonGetText }

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cast { Int, Float, Text, Bool, Timestamp }

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum F {
    Upper, Lower, Length, Substr, Replace, Trim, Ltrim, Rtrim, Instr, Concat, ConcatWs, Left, Right, Reverse, Repeat, Hex, Typeof,
    Abs, Round, Ceil, Floor, Sqrt, Power, Sign, Mod, Greatest, Least, MinOf, MaxOf,
    Coalesce, Nullif, Iif,
    Now, CurrentDate, Date, Time, Datetime, Strftime, Unixepoch, Extract, TsText,
    JsonExtract, Json, JsonValid, JsonArrayLength, JsonObject, JsonArray, JsonType,
    Uuid, Uuid4,
}

/// A planned scalar expression. `Col` reads the scanned row, `Out` an output column after aggregation (HAVING, an
/// expression over aggregates); `Param` and `Sub` are replaced by values when the statement runs (`bind`).
#[derive(Clone)]
pub enum SExpr {
    Col(usize), Out(usize), Lit(Value), Param(usize), Sub(Arc<crate::sql::SelectPlan>),
    Neg(Box<SExpr>), Not(Box<SExpr>),
    Bin(Op, Box<SExpr>, Box<SExpr>),
    IsNull(Box<SExpr>, bool),
    In(Box<SExpr>, Vec<SExpr>, bool),
    Between(Box<SExpr>, Box<SExpr>, Box<SExpr>, bool),
    Like { e: Box<SExpr>, pat: Box<SExpr>, ci: bool, negated: bool, esc: Option<char> },
    Case { op: Option<Box<SExpr>>, whens: Vec<(SExpr, SExpr)>, els: Option<Box<SExpr>> },
    Cast(Box<SExpr>, Cast),
    Call(F, Vec<SExpr>),
}
impl std::fmt::Debug for SExpr { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "expr") } }

/// The name of a scalar function and its accepted argument counts.
pub fn function(name: &str) -> Option<(F, usize, usize)> {
    Some(match name {
        "upper" => (F::Upper, 1, 1), "lower" => (F::Lower, 1, 1), "length" | "char_length" | "character_length" => (F::Length, 1, 1),
        "substr" | "substring" => (F::Substr, 2, 3), "replace" => (F::Replace, 3, 3), "trim" | "btrim" => (F::Trim, 1, 2), "ltrim" => (F::Ltrim, 1, 2), "rtrim" => (F::Rtrim, 1, 2),
        "instr" => (F::Instr, 2, 2), "concat" => (F::Concat, 1, 64), "concat_ws" => (F::ConcatWs, 2, 64), "left" => (F::Left, 2, 2), "right" => (F::Right, 2, 2),
        "reverse" => (F::Reverse, 1, 1), "repeat" => (F::Repeat, 2, 2), "hex" => (F::Hex, 1, 1), "typeof" => (F::Typeof, 1, 1),
        "abs" => (F::Abs, 1, 1), "round" => (F::Round, 1, 2), "ceil" | "ceiling" => (F::Ceil, 1, 1), "floor" => (F::Floor, 1, 1), "sqrt" => (F::Sqrt, 1, 1),
        "power" | "pow" => (F::Power, 2, 2), "sign" => (F::Sign, 1, 1), "mod" => (F::Mod, 2, 2), "greatest" => (F::Greatest, 1, 64), "least" => (F::Least, 1, 64),
        "coalesce" => (F::Coalesce, 1, 64), "ifnull" => (F::Coalesce, 2, 2), "nullif" => (F::Nullif, 2, 2), "iif" => (F::Iif, 3, 3),
        "now" | "current_timestamp" | "localtimestamp" => (F::Now, 0, 0), "current_date" => (F::CurrentDate, 0, 0),
        "date" => (F::Date, 1, 16), "time" => (F::Time, 1, 16), "datetime" => (F::Datetime, 1, 16), "strftime" => (F::Strftime, 2, 16), "unixepoch" => (F::Unixepoch, 1, 16),
        "json_extract" => (F::JsonExtract, 2, 2), "json" => (F::Json, 1, 1), "json_valid" => (F::JsonValid, 1, 1), "json_array_length" => (F::JsonArrayLength, 1, 2),
        "json_object" => (F::JsonObject, 0, 64), "json_array" => (F::JsonArray, 0, 64), "json_type" => (F::JsonType, 1, 2),
        "uuid" | "uuid7" => (F::Uuid, 0, 0), "gen_random_uuid" | "uuid4" => (F::Uuid4, 0, 0),
        _ => return None,
    })
}

impl SExpr {
    pub fn lit(v: Value) -> SExpr { SExpr::Lit(v) }
    pub fn bx(self) -> Box<SExpr> { Box::new(self) }
    /// Visit every node (used to find columns, subqueries and parameters).
    pub fn walk(&self, f: &mut dyn FnMut(&SExpr)) {
        f(self);
        match self {
            SExpr::Neg(a) | SExpr::Not(a) | SExpr::IsNull(a, _) | SExpr::Cast(a, _) => a.walk(f),
            SExpr::Bin(_, a, b) => { a.walk(f); b.walk(f); }
            SExpr::In(a, l, _) => { a.walk(f); for x in l { x.walk(f); } }
            SExpr::Between(a, b, c, _) => { a.walk(f); b.walk(f); c.walk(f); }
            SExpr::Like { e, pat, .. } => { e.walk(f); pat.walk(f); }
            SExpr::Case { op, whens, els } => { if let Some(o) = op { o.walk(f); } for (w, t) in whens { w.walk(f); t.walk(f); } if let Some(e) = els { e.walk(f); } }
            SExpr::Call(_, args) => for a in args { a.walk(f); },
            _ => {}
        }
    }
    /// A copy with parameters and scalar subqueries replaced by their values for this execution.
    pub fn bind(&self, params: &[Value], sub: &mut dyn FnMut(&Arc<crate::sql::SelectPlan>) -> Result<Value, String>) -> Result<SExpr, String> {
        let b = |x: &SExpr, sub: &mut dyn FnMut(&Arc<crate::sql::SelectPlan>) -> Result<Value, String>| x.bind(params, sub);
        Ok(match self {
            SExpr::Param(i) => SExpr::Lit(params.get(*i).cloned().ok_or(format!("missing parameter {}", i + 1))?),
            SExpr::Sub(q) => SExpr::Lit(sub(q)?),
            SExpr::Neg(a) => SExpr::Neg(b(a, sub)?.bx()), SExpr::Not(a) => SExpr::Not(b(a, sub)?.bx()),
            SExpr::IsNull(a, n) => SExpr::IsNull(b(a, sub)?.bx(), *n), SExpr::Cast(a, c) => SExpr::Cast(b(a, sub)?.bx(), *c),
            SExpr::Bin(o, x, y) => SExpr::Bin(*o, b(x, sub)?.bx(), b(y, sub)?.bx()),
            SExpr::In(a, l, n) => SExpr::In(b(a, sub)?.bx(), l.iter().map(|x| b(x, sub)).collect::<Result<_, _>>()?, *n),
            SExpr::Between(a, lo, hi, n) => SExpr::Between(b(a, sub)?.bx(), b(lo, sub)?.bx(), b(hi, sub)?.bx(), *n),
            SExpr::Like { e, pat, ci, negated, esc } => SExpr::Like { e: b(e, sub)?.bx(), pat: b(pat, sub)?.bx(), ci: *ci, negated: *negated, esc: *esc },
            SExpr::Case { op, whens, els } => SExpr::Case { op: op.as_ref().map(|o| b(o, sub).map(|x| x.bx())).transpose()?, whens: whens.iter().map(|(w, t)| Ok((b(w, sub)?, b(t, sub)?))).collect::<Result<_, String>>()?, els: els.as_ref().map(|e| b(e, sub).map(|x| x.bx())).transpose()? },
            SExpr::Call(f, args) => SExpr::Call(*f, args.iter().map(|x| b(x, sub)).collect::<Result<_, _>>()?),
            other => other.clone(),
        })
    }
    /// The static type, when it is known: what the console shows, and how a TIMESTAMP compares with a text literal.
    pub fn ty(&self, col: &dyn Fn(usize) -> Option<ColType>) -> Option<ColType> {
        match self {
            SExpr::Col(i) | SExpr::Out(i) => col(*i),
            SExpr::Lit(v) => match v { Value::Int(_) => Some(ColType::Int), Value::Float(_) => Some(ColType::Float), Value::Text(_) => Some(ColType::Text(0)), Value::Bool(_) => Some(ColType::Bool), Value::Bytes(_) => Some(ColType::Bytes(0)), Value::Null => None },
            SExpr::Neg(a) => a.ty(col),
            SExpr::Not(_) | SExpr::IsNull(..) | SExpr::In(..) | SExpr::Between(..) | SExpr::Like { .. } => Some(ColType::Bool),
            SExpr::Bin(op, a, b) => match op {
                Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge | Op::And | Op::Or => Some(ColType::Bool),
                Op::Concat | Op::JsonGet => Some(ColType::Text(0)), Op::JsonGetText => None,
                _ => match (a.ty(col), b.ty(col)) { (Some(ColType::Float), _) | (_, Some(ColType::Float)) => Some(ColType::Float), (Some(ColType::Int | ColType::Timestamp), Some(ColType::Int | ColType::Timestamp)) => Some(ColType::Int), _ => None },
            },
            SExpr::Case { whens, els, .. } => whens.iter().map(|(_, t)| t).chain(els.as_deref()).find_map(|t| t.ty(col)),
            SExpr::Cast(_, c) => Some(match c { Cast::Int => ColType::Int, Cast::Float => ColType::Float, Cast::Text => ColType::Text(0), Cast::Bool => ColType::Bool, Cast::Timestamp => ColType::Timestamp }),
            SExpr::Call(f, args) => match f {
                F::Upper | F::Lower | F::Substr | F::Replace | F::Trim | F::Ltrim | F::Rtrim | F::Concat | F::ConcatWs | F::Left | F::Right | F::Reverse | F::Repeat | F::Hex | F::Typeof
                | F::CurrentDate | F::Date | F::Time | F::Datetime | F::Strftime | F::TsText | F::Json | F::JsonObject | F::JsonArray | F::JsonType => Some(ColType::Text(0)),
                F::Length | F::Instr | F::Sign | F::Unixepoch | F::Extract | F::JsonArrayLength => Some(ColType::Int),
                F::Sqrt | F::Power => Some(ColType::Float), F::JsonValid => Some(ColType::Bool), F::Now => Some(ColType::Timestamp), F::Uuid | F::Uuid4 => Some(ColType::Uuid),
                F::Abs | F::Round | F::Ceil | F::Floor | F::Mod => args.first().and_then(|a| a.ty(col)),
                F::Coalesce | F::Greatest | F::Least | F::MinOf | F::MaxOf | F::Nullif => args.iter().find_map(|a| a.ty(col)),
                F::Iif => args.get(1).and_then(|a| a.ty(col)).or_else(|| args.get(2).and_then(|a| a.ty(col))),
                F::JsonExtract => None,
            },
            SExpr::Param(_) | SExpr::Sub(_) => None,
        }
    }
    /// Compute the value of this planned expression tree for one row (a closed set of SQL operators and functions;
    /// nothing is parsed or executed as code here). `col` decodes the row's columns, or returns the output row's values.
    pub fn eval(&self, col: &dyn Fn(usize) -> Value) -> Result<Value, String> {
        Ok(match self {
            SExpr::Col(i) | SExpr::Out(i) => col(*i),
            SExpr::Lit(v) => v.clone(),
            SExpr::Param(_) | SExpr::Sub(_) => return Err("internal: an expression was not bound before it ran".into()),
            SExpr::Neg(a) => match a.eval(col)? { Value::Null => Value::Null, Value::Int(i) => Value::Int(i.checked_neg().ok_or("integer overflow")?), Value::Float(f) => Value::Float(-f), v => return Err(format!("cannot negate {}", kind(&v))) },
            SExpr::Not(a) => match truth(&a.eval(col)?)? { None => Value::Null, Some(b) => Value::Bool(!b) },
            SExpr::IsNull(a, negated) => Value::Bool((a.eval(col)? == Value::Null) != *negated),
            SExpr::Bin(Op::And, a, b) => match truth(&a.eval(col)?)? { Some(false) => Value::Bool(false), x => match (x, truth(&b.eval(col)?)?) { (_, Some(false)) => Value::Bool(false), (Some(true), Some(true)) => Value::Bool(true), _ => Value::Null } },
            SExpr::Bin(Op::Or, a, b) => match truth(&a.eval(col)?)? { Some(true) => Value::Bool(true), x => match (x, truth(&b.eval(col)?)?) { (_, Some(true)) => Value::Bool(true), (Some(false), Some(false)) => Value::Bool(false), _ => Value::Null } },
            SExpr::Bin(op, a, b) => binary(*op, a.eval(col)?, b.eval(col)?)?,
            SExpr::In(a, list, negated) => {
                let v = a.eval(col)?; if v == Value::Null { return Ok(Value::Null); }
                let mut unknown = false;
                for x in list { match compare(&v, &x.eval(col)?)? { Some(Ordering::Equal) => return Ok(Value::Bool(!negated)), None => unknown = true, _ => {} } }
                if unknown { Value::Null } else { Value::Bool(*negated) }
            }
            SExpr::Between(a, lo, hi, negated) => {
                let v = a.eval(col)?;
                let (x, y) = (compare(&v, &lo.eval(col)?)?, compare(&v, &hi.eval(col)?)?);
                match (x, y) { (Some(x), Some(y)) => Value::Bool((x != Ordering::Less && y != Ordering::Greater) != *negated), _ => Value::Null }
            }
            SExpr::Like { e, pat, ci, negated, esc } => match (e.eval(col)?, pat.eval(col)?) {
                (Value::Null, _) | (_, Value::Null) => Value::Null,
                (Value::Text(s), Value::Text(p)) => Value::Bool(like(&s, &p, *ci, *esc) != *negated),
                (v, _) => return Err(format!("LIKE needs TEXT, got {}", kind(&v))),
            },
            SExpr::Case { op, whens, els } => {
                let base = match op { Some(o) => Some(o.eval(col)?), None => None };
                for (w, t) in whens {
                    let hit = match &base { Some(b) => compare(b, &w.eval(col)?)? == Some(Ordering::Equal), None => truth(&w.eval(col)?)? == Some(true) };
                    if hit { return t.eval(col); }
                }
                match els { Some(e) => e.eval(col)?, None => Value::Null }
            }
            SExpr::Cast(a, c) => cast(a.eval(col)?, *c)?,
            SExpr::Call(f, args) => call(*f, args, col)?,
        })
    }
}

/// A condition's truth: NULL is unknown; booleans and integers (0 is false) are accepted.
pub fn truth(v: &Value) -> Result<Option<bool>, String> {
    match v { Value::Null => Ok(None), Value::Bool(b) => Ok(Some(*b)), Value::Int(i) => Ok(Some(*i != 0)), v => Err(format!("a condition must be BOOLEAN, got {}", kind(v))) }
}
pub fn kind(v: &Value) -> &'static str { match v { Value::Null => "NULL", Value::Int(_) => "INT", Value::Float(_) => "DOUBLE", Value::Bool(_) => "BOOLEAN", Value::Text(_) => "TEXT", Value::Bytes(_) => "BYTES" } }
/// SQL comparison: None when either side is NULL; numbers compare across INT and DOUBLE; other mixed types are an error.
pub fn compare(a: &Value, b: &Value) -> Result<Option<Ordering>, String> {
    Ok(match (a, b) {
        (Value::Null, _) | (_, Value::Null) => None,
        (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
        (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => num(a).partial_cmp(&num(b)),
        (Value::Text(x), Value::Text(y)) => Some(x.cmp(y)), (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)), (Value::Bytes(x), Value::Bytes(y)) => Some(x.cmp(y)),
        _ => return Err(format!("cannot compare {} with {}", kind(a), kind(b))),
    })
}
fn num(v: &Value) -> f64 { match v { Value::Int(i) => *i as f64, Value::Float(f) => *f, _ => 0.0 } }
/// A number as text the way SQL writes it: integral floats keep one decimal.
pub fn num_text(v: &Value) -> String { match v { Value::Int(i) => i.to_string(), Value::Float(f) => if f.fract() == 0.0 && f.abs() < 1e15 { format!("{f:.1}") } else { format!("{f}") }, Value::Bool(b) => b.to_string(), Value::Text(s) => s.clone(), _ => String::new() } }

fn binary(op: Op, a: Value, b: Value) -> Result<Value, String> {
    use Value::*;
    if matches!(op, Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge) {
        return Ok(match compare(&a, &b)? { None => Null, Some(o) => Bool(match op { Op::Eq => o.is_eq(), Op::Ne => o.is_ne(), Op::Lt => o.is_lt(), Op::Le => o.is_le(), Op::Gt => o.is_gt(), _ => o.is_ge() }) });
    }
    if a == Null || b == Null { return Ok(Null); }
    Ok(match op {
        Op::Concat => match (&a, &b) { (Bytes(_), _) | (_, Bytes(_)) => return Err("|| needs text or numbers".into()), _ => Text(num_text(&a) + &num_text(&b)) },
        Op::JsonGet | Op::JsonGetText => {
            let Text(doc) = &a else { return Err(format!("-> needs JSON text, got {}", kind(&a))) };
            let path = match &b { Text(p) if p.starts_with('$') => p.clone(), Text(k) => format!("$.\"{k}\""), Int(i) => format!("$[{i}]"), other => return Err(format!("-> needs a key, a path or an index, got {}", kind(other))) };
            let v = json_at(doc, &path)?;
            match v { None => Null, Some(j) => if op == Op::JsonGet { Text(j.to_string()) } else { json_to_value(&j) } }
        }
        _ => match (&a, &b) {
            (Int(x), Int(y)) => match op {
                Op::Add => Int(x.checked_add(*y).ok_or("integer overflow")?), Op::Sub => Int(x.checked_sub(*y).ok_or("integer overflow")?), Op::Mul => Int(x.checked_mul(*y).ok_or("integer overflow")?),
                Op::Div => { if *y == 0 { return Err("division by zero".into()); } Int(x.checked_div(*y).ok_or("integer overflow")?) }
                Op::Mod => { if *y == 0 { return Err("division by zero".into()); } Int(x.checked_rem(*y).ok_or("integer overflow")?) }
                _ => unreachable!(),
            },
            (Int(_) | Float(_), Int(_) | Float(_)) => { let (x, y) = (num(&a), num(&b)); match op {
                Op::Add => Float(x + y), Op::Sub => Float(x - y), Op::Mul => Float(x * y),
                Op::Div => { if y == 0.0 { return Err("division by zero".into()); } Float(x / y) }
                Op::Mod => { if y == 0.0 { return Err("division by zero".into()); } Float(x % y) }
                _ => unreachable!() } }
            _ => return Err(format!("cannot apply {} to {} and {}", match op { Op::Add => "+", Op::Sub => "-", Op::Mul => "*", Op::Div => "/", _ => "%" }, kind(&a), kind(&b))),
        },
    })
}

/// LIKE: `%` any run, `_` one character, `esc` before either makes it literal; `ci` compares lowercase (ILIKE).
pub fn like(s: &str, p: &str, ci: bool, esc: Option<char>) -> bool {
    let (s, p): (Vec<char>, Vec<char>) = if ci { (s.to_lowercase().chars().collect(), p.to_lowercase().chars().collect()) } else { (s.chars().collect(), p.chars().collect()) };
    // pattern tokens: Some(c) a literal, None for `_`, and `%` as a separate marker
    #[derive(Clone, Copy, PartialEq)] enum T { Lit(char), One, Any }
    let mut toks = vec![]; let mut i = 0;
    while i < p.len() { let c = p[i]; if Some(c) == esc && i + 1 < p.len() { toks.push(T::Lit(p[i + 1])); i += 2; continue; } toks.push(match c { '%' => T::Any, '_' => T::One, c => T::Lit(c) }); i += 1; }
    let (mut si, mut ti) = (0usize, 0usize); let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if ti < toks.len() && match toks[ti] { T::Lit(c) => c == s[si], T::One => true, T::Any => false } { si += 1; ti += 1; }
        else if ti < toks.len() && toks[ti] == T::Any { star = Some((ti, si)); ti += 1; }
        else if let Some((st, ss)) = star { ti = st + 1; si = ss + 1; star = Some((st, ss + 1)); }
        else { return false; }
    }
    while ti < toks.len() && toks[ti] == T::Any { ti += 1; }
    ti == toks.len()
}

fn cast(v: Value, c: Cast) -> Result<Value, String> {
    use Value::*;
    if v == Null { return Ok(Null); }
    Ok(match c {
        Cast::Int => match v { Int(i) => Int(i), Float(f) => { if !f.is_finite() || f.abs() >= 9.2e18 { return Err("integer overflow".into()); } Int(f.trunc() as i64) } Bool(b) => Int(b as i64), Text(s) => Int(s.trim().parse::<i64>().or_else(|_| s.trim().parse::<f64>().map(|f| f.trunc() as i64)).map_err(|_| format!("cannot cast {s:?} to INT"))?), Bytes(_) => return Err("cannot cast BYTES to INT".into()), Null => Null },
        Cast::Float => match v { Int(i) => Float(i as f64), Float(f) => Float(f), Bool(b) => Float(b as i64 as f64), Text(s) => Float(s.trim().parse::<f64>().map_err(|_| format!("cannot cast {s:?} to DOUBLE"))?), _ => return Err("cannot cast BYTES to DOUBLE".into()) },
        Cast::Text => match v { Bytes(b) => Text(String::from_utf8_lossy(&b).into_owned()), v => Text(num_text(&v)) },
        Cast::Bool => match v { Bool(b) => Bool(b), Int(i) => Bool(i != 0), Text(s) => Bool(match s.trim().to_lowercase().as_str() { "true" | "t" | "1" | "yes" | "y" | "on" => true, "false" | "f" | "0" | "no" | "n" | "off" => false, _ => return Err(format!("cannot cast {s:?} to BOOLEAN")) }), v => return Err(format!("cannot cast {} to BOOLEAN", kind(&v))) },
        Cast::Timestamp => match v { Int(i) => Int(i), Text(s) => Int(parse_timestamp(&s).ok_or(format!("not a timestamp: {s:?}"))?), v => return Err(format!("cannot cast {} to TIMESTAMP", kind(&v))) },
    })
}

fn text_arg(v: &Value, f: &str) -> Result<Option<String>, String> { match v { Value::Null => Ok(None), Value::Text(s) => Ok(Some(s.clone())), v => Err(format!("{f}() needs TEXT, got {}", kind(v))) } }
fn int_arg(v: &Value, f: &str) -> Result<Option<i64>, String> { match v { Value::Null => Ok(None), Value::Int(i) => Ok(Some(*i)), Value::Float(x) if x.fract() == 0.0 => Ok(Some(*x as i64)), v => Err(format!("{f}() needs an integer, got {}", kind(v))) } }

fn call(f: F, args: &[SExpr], col: &dyn Fn(usize) -> Value) -> Result<Value, String> {
    use Value::*;
    // lazy ones first: only some arguments run
    match f {
        F::Coalesce => { for a in args { let v = a.eval(col)?; if v != Null { return Ok(v); } } return Ok(Null); }
        F::Iif => return if truth(&args[0].eval(col)?)? == Some(true) { args[1].eval(col) } else { args[2].eval(col) },
        _ => {}
    }
    let a: Vec<Value> = args.iter().map(|x| x.eval(col)).collect::<Result<_, _>>()?;
    let name = format!("{f:?}").to_lowercase();
    let nullin = || a.iter().any(|v| *v == Null);
    Ok(match f {
        F::Upper => text_arg(&a[0], "upper")?.map(|s| Text(s.to_uppercase())).unwrap_or(Null),
        F::Lower => text_arg(&a[0], "lower")?.map(|s| Text(s.to_lowercase())).unwrap_or(Null),
        F::Length => match &a[0] { Null => Null, Text(s) => Int(s.chars().count() as i64), Bytes(b) => Int(b.len() as i64), v => Int(num_text(v).chars().count() as i64) },
        F::Substr => {
            if nullin() { return Ok(Null); }
            let s: Vec<char> = text_arg(&a[0], "substr")?.unwrap().chars().collect(); let n = s.len() as i64;
            let start = int_arg(&a[1], "substr")?.unwrap(); let len = if a.len() > 2 { Some(int_arg(&a[2], "substr")?.unwrap()) } else { None };
            // SQLite: positions from 1; 0 or negative start counts from the end or shortens the length
            let (mut from, mut to) = if start > 0 { (start - 1, len.map(|l| start - 1 + l).unwrap_or(n)) } else if start == 0 { (0, len.map(|l| l - 1).unwrap_or(n)) } else { (n + start, len.map(|l| n + start + l).unwrap_or(n)) };
            if let Some(l) = len { if l < 0 { to = from; from += l; } }
            let (from, to) = (from.clamp(0, n) as usize, to.clamp(0, n) as usize);
            Text(if from < to { s[from..to].iter().collect() } else { String::new() })
        }
        F::Replace => { if nullin() { return Ok(Null); } let (s, x, y) = (text_arg(&a[0], "replace")?.unwrap(), text_arg(&a[1], "replace")?.unwrap(), text_arg(&a[2], "replace")?.unwrap()); Text(if x.is_empty() { s } else { s.replace(&x, &y) }) }
        F::Trim | F::Ltrim | F::Rtrim => {
            if nullin() { return Ok(Null); }
            let s = text_arg(&a[0], &name)?.unwrap(); let set: Vec<char> = if a.len() > 1 { text_arg(&a[1], &name)?.unwrap().chars().collect() } else { vec![' '] };
            let p = |c: char| set.contains(&c);
            Text(match f { F::Trim => s.trim_matches(p).to_string(), F::Ltrim => s.trim_start_matches(p).to_string(), _ => s.trim_end_matches(p).to_string() })
        }
        F::Instr => { if nullin() { return Ok(Null); } let (s, x) = (text_arg(&a[0], "instr")?.unwrap(), text_arg(&a[1], "instr")?.unwrap()); Int(s.find(&x).map(|b| s[..b].chars().count() as i64 + 1).unwrap_or(0)) }
        F::Concat => Text(a.iter().filter(|v| **v != Null).map(num_text).collect()),
        F::ConcatWs => { if a[0] == Null { return Ok(Null); } let sep = num_text(&a[0]); Text(a[1..].iter().filter(|v| **v != Null).map(num_text).collect::<Vec<_>>().join(&sep)) }
        F::Left | F::Right => { if nullin() { return Ok(Null); } let s: Vec<char> = text_arg(&a[0], &name)?.unwrap().chars().collect(); let k = int_arg(&a[1], &name)?.unwrap().max(0) as usize; let k = k.min(s.len()); Text(if f == F::Left { s[..k].iter().collect() } else { s[s.len() - k..].iter().collect() }) }
        F::Reverse => text_arg(&a[0], "reverse")?.map(|s| Text(s.chars().rev().collect())).unwrap_or(Null),
        F::Repeat => { if nullin() { return Ok(Null); } let k = int_arg(&a[1], "repeat")?.unwrap(); if !(0..=1_000_000).contains(&k) { return Err("repeat() count must be between 0 and 1000000".into()); } Text(text_arg(&a[0], "repeat")?.unwrap().repeat(k as usize)) }
        F::Hex => match &a[0] { Null => Null, Bytes(b) => Text(b.iter().map(|x| format!("{x:02X}")).collect()), v => Text(num_text(v).bytes().map(|x| format!("{x:02X}")).collect()) },
        F::Typeof => Text(match &a[0] { Null => "null", Int(_) => "integer", Float(_) => "real", Text(_) => "text", Bytes(_) => "blob", Bool(_) => "boolean" }.into()),
        F::Abs => match &a[0] { Null => Null, Int(i) => Int(i.checked_abs().ok_or("integer overflow")?), Float(x) => Float(x.abs()), v => return Err(format!("abs() needs a number, got {}", kind(v))) },
        F::Round => {
            if nullin() { return Ok(Null); }
            let d = if a.len() > 1 { int_arg(&a[1], "round")?.unwrap() } else { 0 };
            match &a[0] { Int(i) => Int(*i), Float(x) => { let m = 10f64.powi(d.clamp(-15, 15) as i32); Float((x * m).round() / m) } v => return Err(format!("round() needs a number, got {}", kind(v))) }
        }
        F::Ceil | F::Floor => match &a[0] { Null => Null, Int(i) => Int(*i), Float(x) => Float(if f == F::Ceil { x.ceil() } else { x.floor() }), v => return Err(format!("{name}() needs a number, got {}", kind(v))) },
        F::Sqrt => match &a[0] { Null => Null, Int(_) | Float(_) => { let x = num(&a[0]); if x < 0.0 { return Err("sqrt() of a negative number".into()); } Float(x.sqrt()) } v => return Err(format!("sqrt() needs a number, got {}", kind(v))) },
        F::Power => { if nullin() { return Ok(Null); } if !matches!(a[0], Int(_) | Float(_)) || !matches!(a[1], Int(_) | Float(_)) { return Err("power() needs numbers".into()); } Float(num(&a[0]).powf(num(&a[1]))) }
        F::Sign => match &a[0] { Null => Null, Int(i) => Int(i.signum()), Float(x) => Int(if *x > 0.0 { 1 } else if *x < 0.0 { -1 } else { 0 }), v => return Err(format!("sign() needs a number, got {}", kind(v))) },
        F::Mod => binary(Op::Mod, a[0].clone(), a[1].clone())?,
        F::Greatest | F::Least => { let mut best: Option<Value> = None; for v in a.iter().filter(|v| **v != Null) { let take = match &best { None => true, Some(b) => { let o = compare(v, b)?.unwrap(); if f == F::Greatest { o.is_gt() } else { o.is_lt() } } }; if take { best = Some(v.clone()); } } best.unwrap_or(Null) }
        F::MinOf | F::MaxOf => { if nullin() { return Ok(Null); } let mut best = a[0].clone(); for v in &a[1..] { let o = compare(v, &best)?.unwrap(); if (f == F::MaxOf && o.is_gt()) || (f == F::MinOf && o.is_lt()) { best = v.clone(); } } best }
        F::Coalesce | F::Iif => unreachable!(),
        F::Nullif => if compare(&a[0], &a[1])? == Some(Ordering::Equal) { Null } else { a[0].clone() },
        F::Now => Int(now_micros()),
        F::CurrentDate => Text(date_text(now_micros())),
        F::Date | F::Time | F::Datetime | F::Unixepoch | F::Strftime => {
            let (fmt, rest) = if f == F::Strftime { (Some(text_arg(&a[0], "strftime")?), &a[1..]) } else { (None, &a[..]) };
            if fmt == Some(None) { return Ok(Null); }
            let Some(us) = moment(&rest[0], &rest[1..])? else { return Ok(Null) };
            match f { F::Date => Text(date_text(us)), F::Time => Text(clock_text(us)), F::Datetime => Text(format!("{} {}", date_text(us), clock_text(us))), F::Unixepoch => Int(us.div_euclid(1_000_000)), _ => Text(strftime(&fmt.unwrap().unwrap(), us)?) }
        }
        F::Extract => { let Some(part) = text_arg(&a[0], "extract")? else { return Ok(Null) }; let Some(us) = moment(&a[1], &[])? else { return Ok(Null) }; extract(&part, us)? }
        F::TsText => match &a[0] { Null => Null, Int(us) => Text(crate::table::format_timestamp(*us)), v => Text(num_text(v)) },
        F::JsonExtract => { if nullin() { return Ok(Null); } let doc = text_arg(&a[0], "json_extract")?.unwrap(); let path = text_arg(&a[1], "json_extract")?.unwrap(); match json_at(&doc, &path)? { None => Null, Some(j) => json_to_value(&j) } }
        F::Json => match &a[0] { Null => Null, Text(s) => Text(serde_json::from_str::<serde_json::Value>(s).map_err(|e| format!("malformed JSON: {e}"))?.to_string()), v => return Err(format!("json() needs TEXT, got {}", kind(v))) },
        F::JsonValid => match &a[0] { Null => Null, Text(s) => Bool(serde_json::from_str::<serde_json::Value>(s).is_ok()), _ => Bool(false) },
        F::JsonArrayLength | F::JsonType => {
            if nullin() { return Ok(Null); }
            let doc = text_arg(&a[0], &name)?.unwrap(); let path = if a.len() > 1 { text_arg(&a[1], &name)?.unwrap() } else { "$".into() };
            match json_at(&doc, &path)? { None => Null, Some(j) => if f == F::JsonType { Text(match j { serde_json::Value::Null => "null", serde_json::Value::Bool(true) => "true", serde_json::Value::Bool(false) => "false", serde_json::Value::Number(n) => if n.is_f64() { "real" } else { "integer" }, serde_json::Value::String(_) => "text", serde_json::Value::Array(_) => "array", serde_json::Value::Object(_) => "object" }.into()) } else { Int(j.as_array().map(|x| x.len() as i64).unwrap_or(0)) } }
        }
        F::JsonObject => { if a.len() % 2 != 0 { return Err("json_object() needs key, value pairs".into()); } let mut m = serde_json::Map::new(); for kv in a.chunks(2) { let k = text_arg(&kv[0], "json_object")?.ok_or("json_object() keys cannot be NULL")?; m.insert(k, value_to_json(&kv[1])); } Text(serde_json::Value::Object(m).to_string()) }
        F::JsonArray => Text(serde_json::Value::Array(a.iter().map(value_to_json).collect()).to_string()),
        F::Uuid => Text(format_uuid(&uuid_v7())), F::Uuid4 => Text(format_uuid(&uuid_v4())),
    })
}

// ---- dates: TIMESTAMP values are microseconds since 1970 (UTC); text in the forms `parse_timestamp` reads, or 'now'

fn civil(us: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let secs = us.div_euclid(1_000_000); let frac = us.rem_euclid(1_000_000); let days = secs.div_euclid(86400); let sod = secs.rem_euclid(86400);
    let z = days + 719468; let era = z.div_euclid(146097); let doe = z - era * 146097; let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1; let m = if mp < 10 { mp + 3 } else { mp - 9 }; let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, sod / 3600, sod % 3600 / 60, sod % 60, frac)
}
fn from_civil(y: i64, m: i64, d: i64) -> i64 { let (yy, mp) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) }; let era = yy.div_euclid(400); let yoe = yy - era * 400; let doy = (153 * mp + 2) / 5 + d - 1; let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; era * 146097 + doe - 719468 }
fn date_text(us: i64) -> String { let (y, m, d, ..) = civil(us); format!("{y:04}-{m:02}-{d:02}") }
fn clock_text(us: i64) -> String { let (_, _, _, h, mi, s, _) = civil(us); format!("{h:02}:{mi:02}:{s:02}") }
/// The moment a date function works on: a TIMESTAMP (microseconds), text, or 'now', then SQLite-style modifiers.
fn moment(v: &Value, mods: &[Value]) -> Result<Option<i64>, String> {
    let mut unix = false;
    for m in mods { if let Value::Text(t) = m { if t.trim().eq_ignore_ascii_case("unixepoch") { unix = true; } } }
    let mut us = match v {
        Value::Null => return Ok(None),
        Value::Int(i) => if unix { i.checked_mul(1_000_000).ok_or("integer overflow")? } else { *i },
        Value::Float(f) if unix => (f * 1e6) as i64,
        Value::Text(s) if s.trim().eq_ignore_ascii_case("now") => now_micros(),
        Value::Text(s) => match parse_timestamp(s) { Some(x) => x, None => return Ok(None) },
        v => return Err(format!("a date needs TEXT or a TIMESTAMP, got {}", kind(v))),
    };
    for m in mods {
        let Value::Text(t) = m else { if *m == Value::Null { return Ok(None); } return Err("date modifiers are text, like '+1 day'".into()) };
        let t = t.trim().to_lowercase();
        if t == "unixepoch" || t == "utc" { continue; }
        if let Some(unit) = t.strip_prefix("start of ") {
            let (y, mo, d, ..) = civil(us);
            us = match unit { "day" => from_civil(y, mo, d), "month" => from_civil(y, mo, 1), "year" => from_civil(y, 1, 1), _ => return Err(format!("unknown date modifier {t:?}")) } * 86_400_000_000;
            continue;
        }
        let mut parts = t.split_whitespace();
        let (Some(n), Some(unit), None) = (parts.next(), parts.next(), parts.next()) else { return Err(format!("unknown date modifier {t:?}")) };
        let n: f64 = n.parse().map_err(|_| format!("unknown date modifier {t:?}"))?;
        let unit = unit.trim_end_matches('s');
        us = match unit {
            "second" => us + (n * 1e6) as i64, "minute" => us + (n * 60e6) as i64, "hour" => us + (n * 3600e6) as i64, "day" => us + (n * 86400e6) as i64,
            "month" | "year" => {
                if n.fract() != 0.0 { return Err(format!("{unit}s must be whole: {t:?}")); }
                let (y, mo, d, ..) = civil(us); let total = y * 12 + (mo - 1) + n as i64 * if unit == "year" { 12 } else { 1 };
                let tod = us.rem_euclid(86_400_000_000);
                // SQLite normalizes an overflowing day (Jan 31 + 1 month = Mar 3 or 2): add the days past the month's end
                (from_civil(total.div_euclid(12), total.rem_euclid(12) + 1, 1) + d - 1) * 86_400_000_000 + tod
            }
            _ => return Err(format!("unknown date modifier {t:?}")),
        };
    }
    Ok(Some(us))
}
fn strftime(fmt: &str, us: i64) -> Result<String, String> {
    let (y, m, d, h, mi, s, frac) = civil(us); let mut out = String::new(); let mut it = fmt.chars();
    let doy = from_civil(y, m, d) - from_civil(y, 1, 1) + 1; let dow = (from_civil(y, m, d) + 4).rem_euclid(7);
    while let Some(c) = it.next() {
        if c != '%' { out.push(c); continue; }
        match it.next() {
            Some('Y') => out += &format!("{y:04}"), Some('m') => out += &format!("{m:02}"), Some('d') => out += &format!("{d:02}"), Some('H') => out += &format!("{h:02}"),
            Some('M') => out += &format!("{mi:02}"), Some('S') => out += &format!("{s:02}"), Some('f') => out += &format!("{s:02}.{:03}", frac / 1000), Some('s') => out += &us.div_euclid(1_000_000).to_string(),
            Some('j') => out += &format!("{doy:03}"), Some('w') => out += &dow.to_string(), Some('%') => out.push('%'),
            other => return Err(format!("strftime(): unsupported format %{}", other.map(String::from).unwrap_or_default())),
        }
    }
    Ok(out)
}
fn extract(part: &str, us: i64) -> Result<Value, String> {
    let (y, m, d, h, mi, s, frac) = civil(us);
    Ok(Value::Int(match part.to_lowercase().as_str() {
        "year" => y, "month" => m, "day" => d, "hour" => h, "minute" => mi, "second" => s, "microsecond" | "microseconds" => s * 1_000_000 + frac,
        "dow" => (from_civil(y, m, d) + 4).rem_euclid(7), "doy" => from_civil(y, m, d) - from_civil(y, 1, 1) + 1, "epoch" => us.div_euclid(1_000_000),
        "quarter" => (m - 1) / 3 + 1, "week" => { let doy = from_civil(y, m, d) - from_civil(y, 1, 1); doy / 7 + 1 }
        other => return Err(format!("EXTRACT({other} …) is not supported")),
    }))
}

// ---- JSON (serde_json); paths are SQLite's: $, .key, ."key", [n], [#-n]

fn json_at(doc: &str, path: &str) -> Result<Option<serde_json::Value>, String> {
    let root: serde_json::Value = serde_json::from_str(doc).map_err(|e| format!("malformed JSON: {e}"))?;
    let p = path.trim(); let Some(mut rest) = p.strip_prefix('$') else { return Err(format!("a JSON path starts with $: {path:?}")) };
    let mut cur = &root;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('.') {
            let (key, r2) = if let Some(q) = r.strip_prefix('"') { let end = q.find('"').ok_or(format!("bad JSON path {path:?}"))?; (&q[..end], &q[end + 1..]) } else { let end = r.find(['.', '[']).unwrap_or(r.len()); (&r[..end], &r[end..]) };
            match cur.get(key) { Some(v) => cur = v, None => return Ok(None) }
            rest = r2;
        } else if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']').ok_or(format!("bad JSON path {path:?}"))?; let idx = r[..end].trim();
            let arr = match cur.as_array() { Some(a) => a, None => return Ok(None) };
            let i = if let Some(back) = idx.strip_prefix("#-") { let k: usize = back.parse().map_err(|_| format!("bad JSON path {path:?}"))?; if k > arr.len() { return Ok(None); } arr.len() - k } else { idx.parse::<usize>().map_err(|_| format!("bad JSON path {path:?}"))? };
            match arr.get(i) { Some(v) => cur = v, None => return Ok(None) }
            rest = &r[end + 1..];
        } else { return Err(format!("bad JSON path {path:?}")); }
    }
    Ok(Some(cur.clone()))
}
fn json_to_value(j: &serde_json::Value) -> Value {
    match j { serde_json::Value::Null => Value::Null, serde_json::Value::Bool(b) => Value::Bool(*b), serde_json::Value::Number(n) => n.as_i64().map(Value::Int).unwrap_or_else(|| Value::Float(n.as_f64().unwrap_or(0.0))), serde_json::Value::String(s) => Value::Text(s.clone()), other => Value::Text(other.to_string()) }
}
fn value_to_json(v: &Value) -> serde_json::Value {
    match v { Value::Null => serde_json::Value::Null, Value::Int(i) => (*i).into(), Value::Float(f) => serde_json::Number::from_f64(*f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null), Value::Bool(b) => (*b).into(), Value::Text(s) => s.clone().into(), Value::Bytes(b) => format_uuid_or_hex(b).into() }
}
fn format_uuid_or_hex(b: &[u8]) -> String { if b.len() == 16 { format_uuid(b) } else { b.iter().map(|x| format!("{x:02x}")).collect() } }
/// Normalize a UUID literal so it compares equal to the column's decoded form (lowercase, hyphenated).
pub fn uuid_text(s: &str) -> Option<String> { parse_uuid(s).map(|b| format_uuid(&b)) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn like_patterns() {
        assert!(like("alice", "a%", false, None)); assert!(!like("Alice", "a%", false, None)); assert!(like("Alice", "a%", true, None));
        assert!(like("abc", "a_c", false, None)); assert!(like("abc", "%c", false, None)); assert!(like("a%c", "a\\%c", false, Some('\\'))); assert!(!like("abc", "a\\%c", false, Some('\\')));
        assert!(like("", "%", false, None)); assert!(!like("", "_", false, None)); assert!(like("mississippi", "%ss%pi", false, None)); assert!(like("héllo", "h_llo", false, None));
    }
    #[test] fn dates() {
        let d = |s: &str, m: &[&str]| moment(&Value::Text(s.into()), &m.iter().map(|x| Value::Text(x.to_string())).collect::<Vec<_>>()).unwrap().map(date_text);
        assert_eq!(d("2026-10-17", &["+1 day"]).unwrap(), "2026-10-18"); assert_eq!(d("2026-01-31", &["+1 month"]).unwrap(), "2026-03-03");
        assert_eq!(d("2026-10-17 13:45:00", &["start of month"]).unwrap(), "2026-10-01"); assert_eq!(d("2024-02-29", &["+1 year"]).unwrap(), "2025-03-01");
        assert_eq!(strftime("%Y/%m/%d %H:%M:%S %j", parse_timestamp("2026-10-17 13:45:09").unwrap()).unwrap(), "2026/10/17 13:45:09 290");
    }
    #[test] fn json_paths() {
        let doc = r#"{"a":{"b":[1,2,{"c":"x"}]},"t":true}"#;
        assert_eq!(json_to_value(&json_at(doc, "$.a.b[2].c").unwrap().unwrap()), Value::Text("x".into()));
        assert_eq!(json_to_value(&json_at(doc, "$.a.b[#-1]").unwrap().unwrap()), Value::Text(r#"{"c":"x"}"#.into()));
        assert!(json_at(doc, "$.nope").unwrap().is_none()); assert_eq!(json_to_value(&json_at(doc, "$.t").unwrap().unwrap()), Value::Bool(true));
    }
}
