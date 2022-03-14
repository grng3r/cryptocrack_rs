//pub mod bruteforce;
//mod padding_oracle;
pub mod rsa;

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}
