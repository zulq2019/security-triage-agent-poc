using System.Net;

namespace SecAgent.Connectors;

/// <summary>A connector call failed. Messages carry the operation, method, path and status only: never a request body, header or secret.</summary>
public class ConnectorException(string message, bool isTransient = false, HttpStatusCode? statusCode = null, TimeSpan? retryAfter = null, Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>Worth retrying / failing over (timeouts, 408, 429, 5xx, network errors, open circuit).</summary>
    public bool IsTransient { get; } = isTransient;
    public HttpStatusCode? StatusCode { get; } = statusCode;
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>The connection is not usable as configured (missing secret, bad URL, unknown provider). Never transient.</summary>
public sealed class ConnectorConfigurationException(string message, Exception? inner = null) : ConnectorException(message, false, null, null, inner);

/// <summary>The tenant has no connection of the requested kind.</summary>
public sealed class ConnectorNotConfiguredException(string tenantId, ConnectorKind kind)
    : ConnectorException($"Tenant '{tenantId}' has no {kind} connection configured");

/// <summary>Multi-tenant mode: the tenant (or the repository's tenant) is not known. No fallback to another tenant.</summary>
public sealed class UnknownTenantException(string message) : ConnectorException(message);

/// <summary>The connector refused an operation that is never allowed (merge, approve, push to the default branch, force push).</summary>
public sealed class ForbiddenConnectorOperationException(string message) : ConnectorException(message);
