//! CLI command and product-assembly contract tests.

#[cfg(windows)]
#[path = "cli_command_contracts/dispatch_submit_windows.rs"]
mod dispatch_submit_windows;
#[path = "cli_command_contracts/exec_cli_contracts.rs"]
mod exec_cli_contracts;
#[path = "cli_command_contracts/host_lifecycle_cli.rs"]
mod host_lifecycle_cli;
#[path = "cli_command_contracts/host_skip_background_lifecycle_cli.rs"]
mod host_skip_background_lifecycle_cli;
#[path = "cli_command_contracts/host_skip_lifecycle_cli.rs"]
mod host_skip_lifecycle_cli;
#[path = "cli_command_contracts/mcp_add_cli.rs"]
mod mcp_add_cli;
#[path = "cli_command_contracts/plugin_source_cli.rs"]
mod plugin_source_cli;
#[path = "cli_command_contracts/product_assembly_cli.rs"]
mod product_assembly_cli;
