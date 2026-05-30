use std::fmt::{self, Write as _};

use owo_colors::OwoColorize;
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    field::RecordFields,
    fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format::Writer},
    registry::LookupSpan,
};

#[derive(Debug, Clone, Copy)]
pub struct DnsEventFormat;

#[derive(Debug, Clone, Copy)]
pub struct DnsFields;

impl<'writer> FormatFields<'writer> for DnsFields {
    fn format_fields<R>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result
    where
        R: RecordFields,
    {
        let ansi = writer.has_ansi_escapes();
        let mut visitor = FieldWriter {
            writer,
            ansi,
            first: true,
        };

        fields.record(&mut visitor);
        Ok(())
    }
}

impl<S, N> FormatEvent<S, N> for DnsEventFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let ansi = writer.has_ansi_escapes();
        let meta = event.metadata();

        let timestamp = local_timestamp();

        let location = match (meta.file(), meta.line()) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            _ => meta.target().to_string(),
        };

        write!(writer, "{} ", timestamp_fmt(ansi, timestamp))?;
        write!(writer, "{} ", level(meta.level(), ansi))?;
        write!(writer, "{} ", location_fmt(ansi, location))?;

        if let Some(scope) = ctx.event_scope() {
            let mut first_span = true;

            for span in scope.from_root() {
                if !first_span {
                    write!(writer, "{}", punctuation(ansi, " › "))?;
                }

                first_span = false;

                write!(writer, "{}", span_name(ansi, span.name()))?;

                let extensions = span.extensions();

                if let Some(fields) = extensions.get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        write!(
                            writer,
                            "{}{}{}",
                            punctuation(ansi, "{"),
                            fields,
                            punctuation(ansi, "}")
                        )?;
                    }
                }
            }

            if !first_span {
                write!(writer, "{} ", punctuation(ansi, ":"))?;
            }
        }

        let mut visitor = EventVisitor::new(ansi);
        event.record(&mut visitor);

        let has_message = visitor.message.is_some();

        if let Some(message) = visitor.message {
            write!(writer, "{}", message_text(ansi, message))?;
        }

        if !visitor.fields.is_empty() {
            if has_message {
                write!(writer, " ")?;
            }

            write!(writer, "{}", visitor.fields)?;
        }

        writeln!(writer)
    }
}

struct FieldWriter<'writer> {
    writer: Writer<'writer>,
    ansi: bool,
    first: bool,
}

impl Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = self.write_field(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = self.write_field(field, format!("{value:?}"));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        let _ = self.write_field(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        let _ = self.write_field(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        let _ = self.write_field(field, value.to_string());
    }
}

impl FieldWriter<'_> {
    fn write_field(&mut self, field: &Field, value: String) -> fmt::Result {
        if !self.first {
            write!(self.writer, " ")?;
        }

        self.first = false;

        write!(
            self.writer,
            "{}{}{}",
            field_name(self.ansi, field.name()),
            punctuation(self.ansi, "="),
            field_value(self.ansi, value)
        )
    }
}

struct EventVisitor {
    ansi: bool,
    message: Option<String>,
    fields: String,
    first: bool,
}

impl EventVisitor {
    fn new(ansi: bool) -> Self {
        Self {
            ansi,
            message: None,
            fields: String::new(),
            first: true,
        }
    }

    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
            return;
        }

        if !self.first {
            self.fields.push(' ');
        }

        self.first = false;

        let _ = write!(
            self.fields,
            "{}{}{}",
            field_name(self.ansi, field.name()),
            punctuation(self.ansi, "="),
            field_value(self.ansi, value)
        );
    }
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_value(field, value.to_string());
        } else {
            self.record_value(field, format!("{value:?}"));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }
}

fn timestamp_fmt(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().cyan().dimmed().to_string()
    } else {
        value.to_string()
    }
}

fn location_fmt(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().bright_magenta().bold().to_string()
    } else {
        value.to_string()
    }
}

fn span_name(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().bright_cyan().bold().to_string()
    } else {
        value.to_string()
    }
}

fn field_name(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().bright_blue().bold().to_string()
    } else {
        value.to_string()
    }
}

fn field_value(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().yellow().to_string()
    } else {
        value.to_string()
    }
}

fn message_text(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().bright_white().bold().to_string()
    } else {
        value.to_string()
    }
}

fn punctuation(ansi: bool, value: impl fmt::Display) -> String {
    if ansi {
        value.to_string().dimmed().to_string()
    } else {
        value.to_string()
    }
}

fn level(level: &Level, ansi: bool) -> String {
    let value = match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN ",
        Level::INFO => "INFO ",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    };

    if !ansi {
        return value.to_string();
    }

    match *level {
        Level::ERROR => value.bright_red().bold().to_string(),
        Level::WARN => value.bright_yellow().bold().to_string(),
        Level::INFO => value.bright_green().bold().to_string(),
        Level::DEBUG => value.bright_blue().bold().to_string(),
        Level::TRACE => value.bright_magenta().bold().to_string(),
    }
}

fn local_timestamp() -> String {
    let now = match UtcOffset::current_local_offset() {
        Ok(offset) => OffsetDateTime::now_utc().to_offset(offset),
        Err(_) => OffsetDateTime::now_utc(),
    };

    let format = format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3][offset_hour sign:mandatory]:[offset_minute]"
    );

    now.format(format)
        .unwrap_or_else(|_| "time-error".to_string())
}
