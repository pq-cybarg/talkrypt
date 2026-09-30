use talkrypt_core::ChatDescriptor;
fn main() {
    let uri = std::env::args().nth(1).expect("usage: decode_invite <uri>");
    let d = ChatDescriptor::from_uri(&uri).expect("parse failed");
    println!("channel:   {}", d.channel);
    println!("group:     {}", d.group);
    println!("endpoints: {:?}", d.endpoints);
}
