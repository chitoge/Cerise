// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use ::routing::resolving;
use async_trait::async_trait;
use directed_graph::DirectedGraph;
use fuchsia_url::builtin_url::BuiltinUrl;
use include_bytes_from_working_dir::include_bytes_from_working_dir_env;
use routing::resolving::{ComponentAddress, ResolvedComponent, ResolverError};
use thiserror::Error;

use crate::model::resolver::Resolver;

pub static SCHEME: &str = "fuchsia-builtin";

/// The builtin resolver resolves components defined inside component_manager.
///
/// It accepts a URL scheme of the form `fuchsia-builtin://#elf_runner.cm`.
///
/// Builtin component declarations are used to bootstrap the ELF runner.
/// They are never packaged.
///
/// Only absolute URLs are supported.
#[derive(Debug)]
pub struct BuiltinResolver {}

#[async_trait]
impl Resolver for BuiltinResolver {
    async fn resolve(
        &self,
        component_address: &ComponentAddress,
    ) -> Result<ResolvedComponent, ResolverError> {
        if component_address.is_relative_path() {
            return Err(ResolverError::UnexpectedRelativePath(component_address.url().to_string()));
        }
        let url = BuiltinUrl::parse(component_address.url())
            .map_err(|e| ResolverError::malformed_url(e))?;
        let Some(resource) = url.resource() else {
            return Err(ResolverError::manifest_not_found(ManifestNotFoundError(url)));
        };
        let mut dependencies = DirectedGraph::new();
        // CERISE: the builtin .cm blobs are not embedded in this build — the
        // include_bytes_from_working_dir stub yields empty bytes. Cerise resolves
        // elf_runner via the fuchsia-boot resolver (the realm .cml emits /boot/meta/elf_runner.cm),
        // so this builtin path is unused today. Fail loud and clear if anything starts
        // using it (e.g. the FDF dispatcher via fuchsia-builtin://#dispatcher.cm) rather
        // than letting an empty blob surface as a confusing manifest-validation error far
        // away.
        let builtin_bytes = match resource.as_ref() {
            "elf_runner.cm" => Some(ELF_RUNNER_CM_BYTES),
            "dispatcher.cm" => Some(DISPATCHER_CM_BYTES),
            _ => None,
        };
        if let Some(bytes) = builtin_bytes {
            if bytes.is_empty() {
                return Err(ResolverError::manifest_invalid(anyhow::anyhow!(
                    "CERISE: builtin component '{}' is not embedded in this build \
                     (include_bytes_from_working_dir is a stub returning empty bytes). \
                     Embed the real compiled .cm or resolve it via the fuchsia-boot \
                     resolver before using fuchsia-builtin:// for it.",
                    resource.as_ref()
                )));
            }
        }
        let decl = match resource.as_ref() {
            "elf_runner.cm" => {
                resolving::read_and_validate_manifest_bytes(ELF_RUNNER_CM_BYTES, &mut dependencies)?
            }
            "dispatcher.cm" => {
                resolving::read_and_validate_manifest_bytes(DISPATCHER_CM_BYTES, &mut dependencies)?
            }
            _ => return Err(ResolverError::manifest_not_found(ManifestNotFoundError(url.clone()))),
        };

        // Unpackaged components built into component_manager are assigned the
        // platform abi revision.
        let abi_revision = version_history_data::HISTORY.get_abi_revision_for_platform_components();

        Ok(ResolvedComponent {
            context_to_resolve_children: None,
            decl,
            package: None,
            config_values: None,
            abi_revision: Some(abi_revision),
            dependencies,
        })
    }
}

/// A compiled `.cm` binary blob corresponding to the ELF runner component declaration.
static ELF_RUNNER_CM_BYTES: &'static [u8] =
    include_bytes_from_working_dir_env!("ELF_RUNNER_CM_PATH");

/// A compiled `.cm` binary blob corresponding to the dispatcher component declaration.
static DISPATCHER_CM_BYTES: &'static [u8] =
    include_bytes_from_working_dir_env!("DISPATCHER_CM_PATH");

#[derive(Error, Debug, Clone)]
#[error(
    "{0} does not reference a known manifest. Try fuchsia-builtin://#elf_runner.cm or fuchsia-builtin://#dispatcher.cm"
)]
struct ManifestNotFoundError(pub BuiltinUrl);

#[cfg(all(test, not(feature = "src_model_tests")))]
mod tests {
    use super::*;

    #[fuchsia::test]
    fn elf_runner_cm_smoke_test() {
        let decl = resolving::read_and_validate_manifest_bytes(
            ELF_RUNNER_CM_BYTES,
            &mut DirectedGraph::new(),
        )
        .unwrap();
        let program = decl.program.unwrap();
        assert_eq!(program.runner.unwrap().as_str(), "builtin_elf_runner");
    }
}
