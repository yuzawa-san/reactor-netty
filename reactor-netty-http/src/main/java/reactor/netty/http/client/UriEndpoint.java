/*
 * Copyright (c) 2017-2021 VMware, Inc. or its affiliates, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reactor.netty.http.client;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import io.netty.handler.codec.http.HttpUtil;
import io.netty.util.NetUtil;
import reactor.netty.transport.AddressUtils;

final class UriEndpoint {
	static final Pattern SCHEME_PATTERN = Pattern.compile("^\\w+://.*$");
	static final String ROOT_PATH = "/";

	final SocketAddress remoteAddress;
	final URI uri;
	final String scheme;

	private UriEndpoint(URI uri) {
		this(uri, null);
	}

	private UriEndpoint(URI uri, SocketAddress remoteAddress) {
		this.uri = Objects.requireNonNull(uri, "uri");
		if (!uri.isAbsolute()) {
			throw new IllegalArgumentException("URI is not absolute: " + uri);
		}
		if (uri.getHost() == null) {
			throw new IllegalArgumentException("Host is not specified");
		}
		this.scheme = uri.getScheme().toLowerCase();
		if (remoteAddress == null) {
			String host = cleanHostString(uri.getHost());
			int port = uri.getPort() != -1 ? uri.getPort() : (isSecureScheme(scheme) ? 443 : 80);
			this.remoteAddress = AddressUtils.createUnresolved(host, port);
		}
		else {
			this.remoteAddress = remoteAddress;
		}
	}

	static UriEndpoint create(URI uri, String baseUrl, String uriStr, Supplier<? extends SocketAddress> remoteAddress, boolean secure, boolean ws) {
		if (uri != null) {
			// fast path
			return new UriEndpoint(uri);
		}
		if (uriStr == null) {
			uriStr = ROOT_PATH;
		}
		if (baseUrl != null && uriStr.startsWith(ROOT_PATH)) {
			// support prepending a baseUrl
			if (baseUrl.endsWith(ROOT_PATH)) {
				// trim off trailing slash to avoid a double slash when appending uriStr
				baseUrl = baseUrl.substring(0, baseUrl.length() - ROOT_PATH.length());
			}
			uriStr = baseUrl + uriStr;
		}
		if (uriStr.startsWith(ROOT_PATH)) {
			// support "/path" base by prepending scheme and host
			SocketAddress socketAddress = remoteAddress.get();
			uriStr = resolveScheme(secure, ws) + "://" + toSocketAddressStringWithoutDefaultPort(socketAddress, secure) + uriStr;
			return new UriEndpoint(URI.create(uriStr), socketAddress);
		}
		if (!SCHEME_PATTERN.matcher(uriStr).matches()) {
			// support "example.com/path" case by prepending scheme
			uriStr = resolveScheme(secure, ws) + "://" + uriStr;
		}
		return new UriEndpoint(URI.create(uriStr));
	}

	UriEndpoint redirect(String to) {
		try {
			URI redirectUri = new URI(to);
			if (redirectUri.isAbsolute()) {
				// absolute path: treat as a brand new uri
				return new UriEndpoint(redirectUri);
			}
			// relative path: reuse the remote address
			return new UriEndpoint(uri.resolve(redirectUri), remoteAddress);
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Cannot resolve location header", e);
		}
	}

	private static String toSocketAddressStringWithoutDefaultPort(SocketAddress address, boolean secure) {
		if (!(address instanceof InetSocketAddress)) {
			return "localhost";
		}
		String addressString = NetUtil.toSocketAddressString((InetSocketAddress) address);
		if (secure) {
			if (addressString.endsWith(":443")) {
				addressString = addressString.substring(0, addressString.length() - 4);
			}
		}
		else {
			if (addressString.endsWith(":80")) {
				addressString = addressString.substring(0, addressString.length() - 3);
			}
		}
		return addressString;
	}

	private static String cleanHostString(String host) {
		// remove brackets around IPv6 address in host name
		if (host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
			host = host.substring(1, host.length() - 1);
		}
		return host;
	}

	private static String resolveScheme(boolean secure, boolean ws) {
		if (ws) {
			return secure ? HttpClient.WSS_SCHEME : HttpClient.WS_SCHEME;
		}
		else {
			return secure ? HttpClient.HTTPS_SCHEME : HttpClient.HTTP_SCHEME;
		}
	}

	boolean isSecure() {
		return isSecureScheme(scheme);
	}

	static boolean isSecureScheme(String scheme) {
		return HttpClient.HTTPS_SCHEME.equals(scheme) || HttpClient.WSS_SCHEME.equals(scheme);
	}

	private void rawPathAndQuery(StringBuilder sb) {
		String rawPath = uri.getRawPath();
		if (rawPath == null || rawPath.isEmpty()) {
			sb.append('/');
		}
		else {
			sb.append(rawPath);
		}
		String rawQuery = uri.getRawQuery();
		if (rawQuery != null) {
			sb.append('?').append(rawQuery);
		}
	}

	String getRawPathAndQuery() {
		StringBuilder sb = new StringBuilder();
		rawPathAndQuery(sb);
		return sb.toString();
	}

	String getPath() {
		String path = uri.getPath();
		if (path == null || path.isEmpty()) {
			return "/";
		}
		return path;
	}

	String getHostNameHeaderValue() {
		if (remoteAddress instanceof InetSocketAddress) {
			InetSocketAddress address = (InetSocketAddress) remoteAddress;
			String host = HttpUtil.formatHostnameForHttp(address);
			int port = address.getPort();
			if (port != 80 && port != 443) {
				host = host + ':' + port;
			}
			return host;
		}
		else {
			return "localhost";
		}
	}

	SocketAddress getRemoteAddress() {
		return remoteAddress;
	}

	String toExternalForm() {
		StringBuilder sb = new StringBuilder();
		sb.append(scheme);
		sb.append("://");
		sb.append(toSocketAddressStringWithoutDefaultPort(remoteAddress, isSecure()));
		rawPathAndQuery(sb);
		return sb.toString();
	}

	@Override
	public String toString() {
		return toExternalForm();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		UriEndpoint that = (UriEndpoint) o;
		return remoteAddress.equals(that.remoteAddress);
	}

	@Override
	public int hashCode() {
		return Objects.hash(remoteAddress);
	}
}
