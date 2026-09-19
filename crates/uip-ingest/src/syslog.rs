use chrono::{DateTime, Datelike, Local, LocalResult, TimeZone, Utc};

#[derive(Debug, PartialEq)]
pub struct SyslogHeader<'a> {
    pub timestamp: DateTime<Utc>,
    pub host: &'a str,
    pub body: &'a str,
    /// Die Zahl aus `<30>`: Facility mal acht plus Schweregrad. Fehlt sie,
    /// sagt die Zeile nichts über ihre Dringlichkeit — das ist etwas anderes
    /// als „unwichtig", also `None` und nicht 6.
    pub priority: Option<u8>,
}

/// Der Schweregrad aus der Priorität: 0 = Notfall, 7 = Debug.
pub fn severity_of(priority: u8) -> i16 {
    (priority % 8) as i16
}

fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    })
}

/// `now` wird injiziert (Tests!); Produktion ruft `parse_header(line, Utc::now())`.
pub fn parse_header(line: &str, now: DateTime<Utc>) -> Option<SyslogHeader<'_>> {
    // Priority-Präfix <NN> abstreifen — aber den Wert behalten.
    let mut priority = None;
    let line = if let Some(rest) = line.strip_prefix('<') {
        let end = rest.find('>')?;
        if !rest[..end].bytes().all(|b| b.is_ascii_digit()) { return None; }
        priority = rest[..end].parse().ok();
        &rest[end + 1..]
    } else {
        line
    };

    let mut it = line.splitn(2, ' ');
    let month = month_num(it.next()?)?;
    let rest = it.next()?.trim_start();

    let mut it = rest.splitn(2, ' ');
    let day: u32 = it.next()?.parse().ok()?;
    let rest = it.next()?;

    let (time, rest) = rest.split_once(' ')?;

    let mut t = time.splitn(3, ':');
    let (h, m, s): (u32, u32, u32) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );

    let mut it = rest.splitn(2, ' ');
    let host = it.next()?;
    let body = it.next()?.trim_start();
    if host.is_empty() || body.is_empty() { return None; }

    // Syslog-Zeit ist Absender-Lokalzeit; TZ-Env muss dem Gateway entsprechen.
    let local_now = now.with_timezone(&Local);
    let mut year = local_now.year();
    if month as i32 - local_now.month() as i32 > 6 {
        year -= 1;
    }
    let ts = match Local.with_ymd_and_hms(year, month, day, h, m, s) {
        LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => t,
        LocalResult::None => return None, // DST-Lücke
    };

    Some(SyslogHeader { timestamp: ts.with_timezone(&Utc), host, body, priority })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone, Utc};

    fn now() -> chrono::DateTime<Utc> { Utc.with_ymd_and_hms(2026, 9, 13, 12, 0, 0).unwrap() }

    #[test]
    fn parses_plain_header() {
        let h = parse_header("Feb  8 16:43:49 UDR-UK kernel: hello", now()).unwrap();
        assert_eq!(h.host, "UDR-UK");
        assert_eq!(h.body, "kernel: hello");
        assert_eq!(h.timestamp.month(), 2);
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn strips_priority_prefix_but_keeps_the_value() {
        let h = parse_header("<13>Feb  8 16:43:49 UDR kernel: x", now()).unwrap();
        assert_eq!(h.host, "UDR");
        // 13 = Facility 1 (user), Severity 5 (notice).
        assert_eq!(h.priority, Some(13));
        assert_eq!(severity_of(13), 5);
        // Ohne Präfix ist die Dringlichkeit unbekannt, nicht „normal".
        let h = parse_header("Feb  8 16:43:49 UDR kernel: x", now()).unwrap();
        assert_eq!(h.priority, None);
    }

    #[test]
    fn year_rollover_december_log_in_january() {
        let jan = Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap();
        let h = parse_header("Dec 31 23:59:58 UDR kernel: x", jan).unwrap();
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn same_month_keeps_year() {
        let h = parse_header("Sep 13 11:59:00 UDR kernel: x", now()).unwrap();
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_header("not a syslog line", now()).is_none());
        assert!(parse_header("", now()).is_none());
    }
}
