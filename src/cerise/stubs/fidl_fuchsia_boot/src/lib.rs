// Stub for fuchsia.boot FIDL types needed by component_manager.
// Provides correct type signatures so upstream code compiles.
// Not functional — actual boot protocols are provided by userboot.

use fidl::endpoints::{ControlHandle, ProtocolMarker, RequestStream};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use zx::HandleBased;

// ---------- constants ----------
pub const MAX_ARGS_VECTOR_LENGTH: u32 = 4096;
pub const MAX_ARG_NAME_LENGTH: u32 = 256;
pub const MAX_ARG_VALUE_LENGTH: u32 = 4096;
pub const MAX_BOOTLOADER_FILE_LENGTH: u32 = 4096;

// ---------- data types ----------
#[derive(Debug, Clone)]
pub struct BoolPair {
    pub key: String,
    pub defaultval: bool,
}

#[derive(Debug, Clone)]
pub struct ExtraPartition {
    pub n: u32,
}

#[derive(Debug)]
pub struct RetrievedItems {
    pub payload: Option<zx::Vmo>,
    pub length: Option<u32>,
    pub extra: Option<u32>,
}

// ---------- control handle (shared stub) ----------
#[derive(Debug)]
pub struct StubControlHandle;

impl ControlHandle for StubControlHandle {
    fn shutdown(&self) {}
    fn is_closed(&self) -> bool {
        true
    }
    fn on_closed(&self) -> fidl::OnSignalsRef<'_> {
        fidl::OnSignalsRef::pending()
    }
}

// ---------- ReadOnlyLog ----------

pub struct ReadOnlyLogMarker;

impl ProtocolMarker for ReadOnlyLogMarker {
    type Proxy = ReadOnlyLogProxy;
    type RequestStream = ReadOnlyLogRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.ReadOnlyLog";
}

pub struct ReadOnlyLogProxy;

pub struct ReadOnlyLogRequestStream(fidl::Channel);

impl ReadOnlyLogRequestStream {
    pub fn from_channel(channel: fidl::Channel) -> Self {
        ReadOnlyLogRequestStream(channel)
    }
}

impl Stream for ReadOnlyLogRequestStream {
    type Item = Result<ReadOnlyLogRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for ReadOnlyLogRequestStream {
    type Protocol = ReadOnlyLogMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        ReadOnlyLogRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum ReadOnlyLogRequest {
    Get { responder: ReadOnlyLogGetResponder },
}

pub struct ReadOnlyLogGetResponder;

impl ReadOnlyLogGetResponder {
    pub fn send(self, _log: zx::Handle) -> Result<(), fidl::Error> {
        Ok(())
    }
}

// ---------- WriteOnlyLog ----------

pub struct WriteOnlyLogMarker;

impl ProtocolMarker for WriteOnlyLogMarker {
    type Proxy = WriteOnlyLogProxy;
    type RequestStream = WriteOnlyLogRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.WriteOnlyLog";
}

pub struct WriteOnlyLogProxy;

pub struct WriteOnlyLogRequestStream(fidl::Channel);

impl WriteOnlyLogRequestStream {
    pub fn from_channel(channel: fidl::Channel) -> Self {
        WriteOnlyLogRequestStream(channel)
    }
}

impl Stream for WriteOnlyLogRequestStream {
    type Item = Result<WriteOnlyLogRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for WriteOnlyLogRequestStream {
    type Protocol = WriteOnlyLogMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        WriteOnlyLogRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum WriteOnlyLogRequest {
    Get { responder: WriteOnlyLogGetResponder },
}

pub struct WriteOnlyLogGetResponder;

impl WriteOnlyLogGetResponder {
    pub fn send(self, _log: zx::Handle) -> Result<(), fidl::Error> {
        Ok(())
    }
}

// ---------- Arguments ----------

pub struct ArgumentsMarker;

impl ProtocolMarker for ArgumentsMarker {
    type Proxy = ArgumentsProxy;
    type RequestStream = ArgumentsRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.Arguments";
}

pub struct ArgumentsProxy;

pub struct ArgumentsRequestStream(fidl::Channel);

impl Stream for ArgumentsRequestStream {
    type Item = Result<ArgumentsRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for ArgumentsRequestStream {
    type Protocol = ArgumentsMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        ArgumentsRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum ArgumentsRequest {
    GetString { key: String, responder: ArgumentsGetStringResponder },
    GetStrings { keys: Vec<String>, responder: ArgumentsGetStringsResponder },
    GetBool { key: String, defaultval: bool, responder: ArgumentsGetBoolResponder },
    GetBools { keys: Vec<BoolPair>, responder: ArgumentsGetBoolsResponder },
    Collect { prefix: String, responder: ArgumentsCollectResponder },
}

pub struct ArgumentsGetStringResponder;
impl ArgumentsGetStringResponder {
    pub fn send(self, _value: Option<&str>) -> Result<(), fidl::Error> { Ok(()) }
}

pub struct ArgumentsGetStringsResponder;
impl ArgumentsGetStringsResponder {
    pub fn send(self, _values: &[Option<String>]) -> Result<(), fidl::Error> { Ok(()) }
}

pub struct ArgumentsGetBoolResponder;
impl ArgumentsGetBoolResponder {
    pub fn send(self, _value: bool) -> Result<(), fidl::Error> { Ok(()) }
}

pub struct ArgumentsGetBoolsResponder;
impl ArgumentsGetBoolsResponder {
    pub fn send(self, _values: &[bool]) -> Result<(), fidl::Error> { Ok(()) }
}

pub struct ArgumentsCollectResponder;
impl ArgumentsCollectResponder {
    pub fn send(self, _results: &[String]) -> Result<(), fidl::Error> { Ok(()) }
}

// ---------- Items ----------

pub struct ItemsMarker;

impl ProtocolMarker for ItemsMarker {
    type Proxy = ItemsProxy;
    type RequestStream = ItemsRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.Items";
}

pub struct ItemsProxy;

pub struct ItemsRequestStream(fidl::Channel);

impl Stream for ItemsRequestStream {
    type Item = Result<ItemsRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for ItemsRequestStream {
    type Protocol = ItemsMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        ItemsRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum ItemsRequest {
    Get { type_: u32, extra: u32, responder: ItemsGetResponder },
    Get2 { type_: u32, extra: Option<Box<ExtraPartition>>, responder: ItemsGet2Responder },
    GetBootloaderFile { filename: String, responder: ItemsGetBootloaderFileResponder },
}

pub struct ItemsGetResponder;
impl ItemsGetResponder {
    pub fn send(self, _payload: Option<zx::Vmo>, _length: u32) -> Result<(), fidl::Error> {
        Ok(())
    }
}

pub struct ItemsGet2Responder;
impl ItemsGet2Responder {
    pub fn send(self, _result: Result<Vec<RetrievedItems>, i32>) -> Result<(), fidl::Error> {
        Ok(())
    }
}

pub struct ItemsGetBootloaderFileResponder;
impl ItemsGetBootloaderFileResponder {
    pub fn send(self, _payload: Option<zx::Vmo>) -> Result<(), fidl::Error> { Ok(()) }
}

// ---------- FactoryItems ----------

pub struct FactoryItemsMarker;

impl ProtocolMarker for FactoryItemsMarker {
    type Proxy = FactoryItemsProxy;
    type RequestStream = FactoryItemsRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.FactoryItems";
}

pub struct FactoryItemsProxy;

pub struct FactoryItemsRequestStream(fidl::Channel);

impl Stream for FactoryItemsRequestStream {
    type Item = Result<FactoryItemsRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for FactoryItemsRequestStream {
    type Protocol = FactoryItemsMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        FactoryItemsRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum FactoryItemsRequest {
    Get { extra: u32, responder: FactoryItemsGetResponder },
}

pub struct FactoryItemsGetResponder;
impl FactoryItemsGetResponder {
    pub fn send(self, _payload: Option<zx::Vmo>, _length: u32) -> Result<(), fidl::Error> {
        Ok(())
    }
}

// ---------- SvcStashProvider ----------

pub struct SvcStashProviderMarker;

impl ProtocolMarker for SvcStashProviderMarker {
    type Proxy = SvcStashProviderProxy;
    type RequestStream = SvcStashProviderRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.SvcStashProvider";
}

pub struct SvcStashProviderProxy;

pub struct SvcStashProviderRequestStream(fidl::Channel);

impl Stream for SvcStashProviderRequestStream {
    type Item = Result<SvcStashProviderRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for SvcStashProviderRequestStream {
    type Protocol = SvcStashProviderMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        SvcStashProviderRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum SvcStashProviderRequest {
    Get { responder: SvcStashProviderGetResponder },
}

pub struct SvcStashProviderGetResponder;
impl SvcStashProviderGetResponder {
    pub fn send(self, _svc_endpoint: zx::Channel) -> Result<(), fidl::Error> { Ok(()) }
}

// ---------- Userboot ----------

pub struct UserbootMarker;

impl ProtocolMarker for UserbootMarker {
    type Proxy = UserbootProxy;
    type RequestStream = UserbootRequestStream;
    const DEBUG_NAME: &'static str = "fuchsia.boot.Userboot";
}

pub struct UserbootProxy;

pub struct UserbootRequestStream(fidl::Channel);

impl UserbootRequestStream {
    pub fn from_channel(channel: fidl::Channel) -> Self {
        UserbootRequestStream(channel)
    }
}

impl Stream for UserbootRequestStream {
    type Item = Result<UserbootRequest, fidl::Error>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

impl RequestStream for UserbootRequestStream {
    type Protocol = UserbootMarker;
    type ControlHandle = StubControlHandle;
    fn from_channel(channel: fidl::AsyncChannel) -> Self {
        UserbootRequestStream(channel.into_zx_channel())
    }
    fn control_handle(&self) -> Self::ControlHandle {
        StubControlHandle
    }
    fn into_inner(self) -> (fidl::ServeInner<fidl::encoding::DefaultFuchsiaResourceDialect>, bool) {
        unimplemented!()
    }
    fn is_terminated(&self) -> bool {
        true
    }
}

pub enum UserbootRequest {
    PostBootfsFiles { files: Vec<zx::Channel>, responder: UserbootPostBootfsFilesResponder },
}

pub struct UserbootPostBootfsFilesResponder;
impl UserbootPostBootfsFilesResponder {
    pub fn send(self) -> Result<(), fidl::Error> { Ok(()) }
}
