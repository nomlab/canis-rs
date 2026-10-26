mod commands;
mod watcher;
mod processor;
mod adapter;
mod config;
mod observer;
mod error;
mod event;
mod cli;
mod db;

use error::Result;
use cli::{Cli, Commands};
use clap::{Parser};

fn main() -> Result<()> {

    let cli = Cli::parse();

    match cli.command {
        Commands::Init (args) => {
            commands::init::init(args)?;
        },
        Commands::Start (args) => {
            commands::start::start(args)?;
        },
        #[cfg(target_os = "linux")]
        Commands::Stop => {
            commands::stop::stop()?;
        },
        Commands::Info(args) => {
            commands::info::info(args)?;
        },
        Commands::Publish(args) =>{
            commands::publish::publish(args)?;
        },
    }

    Ok(())
}
