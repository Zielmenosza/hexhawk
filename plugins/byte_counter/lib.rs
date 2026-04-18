use crate::plugins::Plugin;

pub struct ByteCounter;

impl Plugin for ByteCounter {
    fn name(&self) -> &'static str { "ByteCounter" }
    fn description(&self) -> &'static str { "Counts file bytes" }
    fn init(&self) { println!("ByteCounter initialized"); }
    fn process(&self, data: &[u8]) -> Result<String, String> {
        Ok(format!("{} bytes", data.len()))
    }
}

pub fn create() -> Box<dyn Plugin> {
    Box::new(ByteCounter)
}