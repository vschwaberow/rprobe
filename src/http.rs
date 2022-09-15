/*
Copyright 2022 Volker Schwaberow <volker@schwaberow.de>
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
Author(s): Volker Schwaberow
*/  


use std::{rc::Rc, ops::Deref};

use crate::getstate::GetState;
#[derive(Debug, Clone, Copy)]
pub struct Http {
    pub timeout: u64,
    pub state_ptr: GetState,
}
  
impl Http {
    pub fn new(timeout: u64, state_ptr: GetState) -> Self {
        Http {
            timeout,
            state_ptr,
        }

    }

    pub fn get_timeout(&self) -> u64 {
        self.timeout
    }


    pub async fn work(&mut self, lines_vec: Rc<Vec<String>>)  {  

        let mut tasks = Vec::new();
        let time = self.get_timeout();
        let ptr = lines_vec.deref().clone();

        for line in ptr  {
                let task = tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let url = line.to_string();
                    let res = client.get(line)
                        .timeout(std::time::Duration::from_secs(time))
                        .send().await;
                    match res {
                        Ok(_) => {
                            println!("{}", url);
                            return true;
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                });
                tasks.push(task);
        }


        for task in tasks {
            let rval = task.await.unwrap();   
            if rval {
                self.state_ptr.add_success();
            } else {
                self.state_ptr.add_failure();
            }

        }


    }
}