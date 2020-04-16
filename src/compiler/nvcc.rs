// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused_imports,dead_code,unused_variables)]

use crate::compiler::{
    gcc,
    Cacheable,
    CompileCommand,
    CompilerArguments,
    write_temp_file,
};
use crate::compiler::args::*;
use crate::compiler::c::{CCompilerImpl, CCompilerKind, Language, ParsedArguments};
use crate::compiler::gcc::ArgData::*;
use crate::dist;
use log::Level::Trace;
use futures::future::{self, Future};
use futures_cpupool::CpuPool;
use crate::mock_command::{
    CommandCreator,
    CommandCreatorSync,
    RunCommand,
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{
    self,
    Write,
};
use std::path::{Path, PathBuf};
use std::process;
use crate::util::{run_input_output, OsStrExt};

use crate::errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct NVCC;

impl CCompilerImpl for NVCC {
    fn kind(&self) -> CCompilerKind { CCompilerKind::NVCC }
    fn parse_arguments(&self,
                       arguments: &[OsString],
                       cwd: &Path) -> CompilerArguments<ParsedArguments>
    {
        gcc::parse_arguments(arguments, cwd, (&gcc::ARGS[..], &ARGS[..]))
    }

    fn preprocess<T>(
        &self,
        creator: &T,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        may_dist: bool,
        rewrite_includes_only: bool,
    ) -> SFuture<process::Output>
    where
        T: CommandCreatorSync,
    {
        preprocess(
            creator,
            executable,
            parsed_args,
            cwd,
            env_vars,
            may_dist,
            self.kind(),
            rewrite_includes_only,
        )
    }

    fn generate_compile_commands(
        &self,
        path_transformer: &mut dist::PathTransformer,
        executable: &Path,
        parsed_args: &ParsedArguments,
        cwd: &Path,
        env_vars: &[(OsString, OsString)],
        rewrite_includes_only: bool,
    ) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
        generate_compile_commands(
            path_transformer,
            executable,
            parsed_args,
            cwd,
            env_vars,
            self.kind(),
            rewrite_includes_only,
        )
    }
}

pub fn preprocess<T>(
    creator: &T,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    may_dist: bool,
    kind: CCompilerKind,
    rewrite_includes_only: bool,
) -> SFuture<process::Output>
where
    T: CommandCreatorSync,
{
    trace!("preprocess");
    let language = match parsed_args.language {
        Language::C => "c",
        Language::Cxx => "c++",
        Language::ObjectiveC => "objective-c",
        Language::ObjectiveCxx => "objective-c++",
    };
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("-E")
        .arg(&parsed_args.input)
        .args(&parsed_args.preprocessor_args)
        .args(&parsed_args.common_args)
        .env_clear()
        .envs(env_vars.iter().map(|&(ref k, ref v)| (k, v)))
        .current_dir(cwd);

    if log_enabled!(Trace) {
        trace!("preprocess: {:?}", cmd);
    }
    run_input_output(cmd, None)
}

pub fn generate_compile_commands(
    path_transformer: &mut dist::PathTransformer,
    executable: &Path,
    parsed_args: &ParsedArguments,
    cwd: &Path,
    env_vars: &[(OsString, OsString)],
    kind: CCompilerKind,
    rewrite_includes_only: bool,
) -> Result<(CompileCommand, Option<dist::CompileCommand>, Cacheable)> {
    // Unused arguments
    {
        let _ = path_transformer;
        let _ = kind;
        let _ = rewrite_includes_only;
    }

    trace!("compile");

    let out_file = match parsed_args.outputs.get("obj") {
        Some(obj) => obj,
        None => return Err("Missing object file output".into()),
    };

    // Pass the language explicitly as we might have gotten it from the
    // command line.
    let language = match parsed_args.language {
        Language::C => "c",
        Language::Cxx => "c++",
        Language::ObjectiveC => "objective-c",
        Language::ObjectiveCxx => "objective-c++",
    };
    let mut arguments: Vec<OsString> = vec![
        "-c".into(),
        parsed_args.input.clone().into(),
        "-o".into(),
        out_file.into(),
    ];
    arguments.extend(parsed_args.preprocessor_args.clone());
    arguments.extend(parsed_args.common_args.clone());
    let command = CompileCommand {
        executable: executable.to_owned(),
        arguments,
        env_vars: env_vars.to_owned(),
        cwd: cwd.to_owned(),
    };

    Ok((command, None, Cacheable::Yes))
}

counted_array!(pub static ARGS: [ArgInfo<gcc::ArgData>; _] = [
    take_arg!("--compiler-bindir", PathBuf, Separated, PassThroughPath),
    take_arg!("--compiler-options", OsString, Separated, PassThrough),
    take_arg!("--std", OsString, Separated, PassThrough),
    take_arg!("-Xcompiler", OsString, Separated, PassThrough),
    take_arg!("-Xfatbin", OsString, Separated, PassThrough),
    take_arg!("-Xptxas", OsString, Separated, PassThrough),
    take_arg!("-ccbin", PathBuf, Separated, PassThroughPath),
    take_arg!("-gencode", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("-maxrregcount", OsString, CanBeSeparated('='), PassThrough),
    take_arg!("-std", OsString, CanBeSeparated('='), PassThrough),
]);

// TODO: add some unit tests
