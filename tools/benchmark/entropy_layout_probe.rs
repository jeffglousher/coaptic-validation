use coaptic::storage::{DatagramIo, Endpoint};
struct Io;
impl DatagramIo for Io {
    type Error=();
    fn recv(&mut self,_:&mut[u8])->Result<Option<(usize,Endpoint)>,()>{Ok(None)}
    fn send(&mut self,_:Endpoint,b:&[u8])->Result<usize,()>{Ok(b.len())}
}
fn main(){
    println!("{{\"kind\":\"fixed_layout\",\"default_bytes\":{},\"constrained_bytes\":{}}}",
        core::mem::size_of::<coaptic::App<coaptic::profiles::Default,Io,1,true>>(),
        core::mem::size_of::<coaptic::App<coaptic::profiles::Constrained,Io,1,false>>());
    #[cfg(feature="alloc")]
    println!("{{\"kind\":\"allocated_layout\",\"memory_bytes\":{},\"default_bytes\":{},\"constrained_bytes\":{}}}",
        core::mem::size_of::<coaptic::storage::AllocMemory>(),
        core::mem::size_of::<coaptic::App<coaptic::profiles::Default,Io,1,true,coaptic::storage::AllocMemory>>(),
        core::mem::size_of::<coaptic::App<coaptic::profiles::Constrained,Io,1,false,coaptic::storage::AllocMemory>>());
    #[cfg(candidate)] {
        // Synthetic callback only for type-layout measurement, never credentials.
        let mut state=1_u64;
        let owned=coaptic::App::profile::<coaptic::profiles::Constrained>().routes::<1>().block_wise::<false>().allow_plaintext()
            .bind_with_entropy(Io,move|bytes|{state=state.wrapping_add(1);bytes.fill(state as u8);true}).unwrap();
        let mut state=1_u64;
        let borrowed=coaptic::App::profile::<coaptic::profiles::Constrained>().routes::<1>().block_wise::<false>().allow_plaintext()
            .bind_with_entropy(Io,|bytes|{state=state.wrapping_add(1);bytes.fill(state as u8);true}).unwrap();
        println!("{{\"kind\":\"entropy_layout\",\"owned_u64_app_bytes\":{},\"borrowed_u64_app_bytes\":{},\"borrowed_external_state_bytes\":8}}",core::mem::size_of_val(&owned),core::mem::size_of_val(&borrowed));
    }
}
