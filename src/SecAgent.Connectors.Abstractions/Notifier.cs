namespace SecAgent.Connectors;

public enum NotificationLevel { Info, Warning, Critical }

public sealed record NotificationFact(string Name, string Value);

/// <summary>A short card (Teams today): run summaries and early warnings. Never contains secret values (callers pass masked text).</summary>
public sealed record Notification(string Title, string Summary, NotificationLevel Level, IReadOnlyList<NotificationFact> Facts,
    string? LinkUrl = null, string? LinkText = null);

public interface INotifierClient
{
    Task NotifyAsync(Notification notification, CancellationToken ct);
}
