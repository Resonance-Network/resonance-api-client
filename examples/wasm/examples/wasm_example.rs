/*
	Copyright 2023 Supercomputing Systems AG
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

//! Example that shows how to detect a runtime update and afterwards update the metadata.

use std::process::ExitCode;

#[no_mangle]
pub extern "C" fn add(lhs: i32, rhs: i32) -> i32 {
	if lhs % 2 == 0 {
		lhs + rhs
	} else {
		lhs - rhs
	}
}

fn main() -> Result<ExitCode, i32> {
	assert!(5 == 5, "x wasn't true!");
	//panic!("x wasn't true!");
	//Err(5)
	Ok(ExitCode::from(1))
}
