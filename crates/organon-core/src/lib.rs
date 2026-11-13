//! The intelligence of organon: it coordinates the organs within a budget, under a policy, and
//! audits what they produce before it enters memory. Pure logic: no files, no processes, no
//! terminal. The `organon` binary does the I/O.
//!
//! - [`budget`]: budgets declared up front per effort; warn at 80%, stop at 100%, and a stop
//!   is final.
//! - [`meter`]: measured spend of a coding-agent session from its transcript.
//! - [`policy`]: allow, ask or deny what an agent is about to do; efforts and routes.
//! - [`route`]: tools first, then a cheap or a strong model; a producer never verifies itself.
//! - [`task`]: a goal with a budget and a trail; an episode when it ends.
//! - [`audit`]: checks a proposal and the organ output it cites before memory sees them.

pub mod audit;
pub mod budget;
pub mod meter;
pub mod policy;
pub mod route;
pub mod task;
pub mod time;
