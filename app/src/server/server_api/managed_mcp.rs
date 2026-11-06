// We don't resolve managed MCPs from agent run CLI flows on WASM, so this code is unused there.
#![cfg_attr(target_family = "wasm", expect(dead_code))]

use ai::agent::action::GitHubTurnReference;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use cynic::MutationBuilder;
#[cfg(test)]
use mockall::automock;
use warp_graphql::mutations::create_managed_mcp_client_config::{
    CreateManagedMcpClientConfig, CreateManagedMcpClientConfigInput,
    CreateManagedMcpClientConfigOutput, CreateManagedMcpClientConfigResult,
    CreateManagedMcpClientConfigVariables, GitHubTurnReferenceInput,
};

use super::ServerApi;
use crate::server::graphql::{get_request_context, get_user_facing_error_message};

#[cfg_attr(test, automock)]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait ManagedMcpClient: 'static + Send + Sync {
    /// `uid` is a managed MCP server UUID or a well-known integration id
    /// (e.g. "linear") — the GraphQL input is an opaque `ID!`.
    async fn create_managed_mcp_client_config(
        &self,
        uid: String,
    ) -> Result<CreateManagedMcpClientConfigOutput>;

    async fn create_github_mcp_client_config(
        &self,
        github_turn: GitHubTurnReference,
    ) -> Result<CreateManagedMcpClientConfigOutput>;
}

pub(crate) fn github_turn_input(
    reference: GitHubTurnReference,
) -> Result<GitHubTurnReferenceInput> {
    Ok(GitHubTurnReferenceInput {
        run_id: reference.run_id.into(),
        execution_id: reference.execution_id.try_into()?,
        input_uid: reference.input_uid.into(),
    })
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl ManagedMcpClient for ServerApi {
    async fn create_managed_mcp_client_config(
        &self,
        uid: String,
    ) -> Result<CreateManagedMcpClientConfigOutput> {
        self.managed_mcp_client_config(uid, None).await
    }

    async fn create_github_mcp_client_config(
        &self,
        github_turn: GitHubTurnReference,
    ) -> Result<CreateManagedMcpClientConfigOutput> {
        self.managed_mcp_client_config("github".to_string(), Some(github_turn_input(github_turn)?))
            .await
    }
}

impl ServerApi {
    async fn managed_mcp_client_config(
        &self,
        uid: String,
        github_turn: Option<GitHubTurnReferenceInput>,
    ) -> Result<CreateManagedMcpClientConfigOutput> {
        let variables = CreateManagedMcpClientConfigVariables {
            input: CreateManagedMcpClientConfigInput {
                uid: cynic::Id::new(uid),
                github_turn,
            },
            request_context: get_request_context(),
        };
        let operation = CreateManagedMcpClientConfig::build(variables);
        let response = self.send_graphql_request(operation, None).await?;

        match response.create_managed_mcp_client_config {
            CreateManagedMcpClientConfigResult::CreateManagedMcpClientConfigOutput(output) => {
                Ok(output)
            }
            CreateManagedMcpClientConfigResult::UserFacingError(error) => {
                Err(anyhow!(get_user_facing_error_message(error)))
            }
            CreateManagedMcpClientConfigResult::Unknown => Err(anyhow!(
                "Unknown error while creating managed MCP client config"
            )),
        }
    }
}
