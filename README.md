DESCRIPTION
============

XRootD Authorization Plugin to be used to forward the client identity
from the Proxy (PSS) server to the back-end storage service.

Under regular circumstances, the Proxy service will use its own identity
when connecting to the back-end storage. By using this plugin, we attempt
to arrange for the client's identity to be sent instead.

In case it is not possible to retrieve the client's identity,
the proxy will continue to use his own.


For this method to work successfully, the SSS security protocol must be used.

IMPLEMENTATION
===============

The Authorization plugin is called in **XrdOfs** every time an operation is attempted.
This makes sure that we have the chance to store the client identity before
communication between the proxy and the back-end starts.

### The XrdSecSSSID Registry

We rely on the SSS protocol to send the identity during the SSS handshake.
To make sure the right identity is sent, we register it in the **XrdSecSSSID** Registry.

In the normal flow of the SSS protocol, if a registry is present,
XrdSecEntity objects are retrieved from it using the connection ID.

However, for the normal flow of the SSS protocol to consider our registry,
we need to have an instance ready by the moment the SSS client is initialized.
This will happen the first time communication is attempted between the PSS and the back-end.

Because of this, we must instantiate the registry as soon as possible, even if we
don't yet have a valid ID to store.

### The ID used by the Proxy

To make sure that the client's identity will be used, we need to store them
in the registry using the same key (ID) that the Proxy will use to start
the connection with the back-end. This very same ID will also be used 
by the SSS protocol to retrieve the proper XrdSecEntity.

The proxy uses the fd part from the **XrdLink::ID**.<sup>1</sup>

E.g.: for the given XrdLink::ID  
`mipatras.1:22@mihai-dell5580` the proxy will retrieve `22` as the connection ID.

We need to make sure we retrieve the same ID in the Authorization plugin.  
To do this (since we don't have access to the XrdLink object), we rely on the value
stored in the **XrdSecEntity::tident**, which has the value of the Link::ID.<sup>2</sup>


DRAWBACKS
==========

1. There is a strong coupling between the way the Proxy and the plugin identify
the connection ID. If the proxy would change the connection ID it uses, 
then the identity saved in the plugin would not be accessible anymore.

2. The Authorization plugin is making a strong assumption that the 
XrdSecEntity::tident has the value of the XrdLink::ID. 
Although true for the XRootD protocol, this is not always the case 
(the XrdHttp protocol, for example).


Dependencies
=============

This plugin requires the XrdSecsssID.hh header from the XrdSecsss module.
