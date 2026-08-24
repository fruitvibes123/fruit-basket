//! box-init — the box PID-1 (post-`switch_root` `/sbin/init`), thin bin entry.
//!
//! All logic lives in the `box_init` library (testable); this maps a fatal `run()` error to a
//! non-zero exit. On the success path `run()` `exec`s into `s6-svscan` and never returns.

#![cfg_attr(not(test), deny(clippy::unwrap_used))]

fn main() {
                                                                                                    
                                                                                              
                                                                                                         
                                                                                                       
                                                                                                          
                                                                                                         
                                                                                                        
                                                                                                             
                                                                                                          
                                                                                                              
      
                                                                                                         
                                                                                                      
                                                
      
                                                                                                          
                                                                                                            
                                                                                                           
                                                         
      
                                                                                                           
                                                                                                            
                                                                                                            
                                                                                                       
                                                                                                     
                                                                                                        
                                          
    unsafe {
        let mut fd = libc::open(c"/dev/kmsg".as_ptr().cast(), libc::O_WRONLY);
        if fd < 0 {
            fd = libc::open(c"/dev/null".as_ptr().cast(), libc::O_RDWR);
        }
        if fd >= 0 {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
    }

                                                                                               
                                                                                                      
                                                                                                          
    std::panic::set_hook(Box::new(|info| box_init::fatal(&format!("panic: {info}"))));

    match box_init::run() {
                                                                                                     
        Ok(never) => match never {},
                                                                                                       
                                                                                                      
                                                                                                  
        Err(e) => box_init::fatal(&format!("run() failed: {e}")),
    }
}
