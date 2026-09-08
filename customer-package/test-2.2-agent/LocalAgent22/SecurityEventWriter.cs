using System.Text.Json;

internal static class SecurityEventWriter
{
    public static async Task WriteAsync(string path, object securityEvent)
    {
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.AppendAllTextAsync(
            path,
            JsonSerializer.Serialize(securityEvent) + Environment.NewLine);
    }
}
