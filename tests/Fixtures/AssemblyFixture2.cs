using System;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace DEXS.Security.DataProtection.Tests.Fixtures
{
    public class AssemblyFixture2 : IDisposable, IAsyncLifetime
    {
        public IMessageSink MessageSink { get; }
        public bool Initialized { get; private set; } = false;
        public static int Count { get; private set; }

        public AssemblyFixture2(IMessageSink messageSink)
        {
            MessageSink = messageSink;
            Count++;
        }

        public void Dispose()
        {
            MessageSink.OnMessage(
                new DiagnosticMessage("AssemblyFixture disposed."));
        }

        public async Task InitializeAsync()
        {
            await Task.Run(() => { Initialized = true; });
        }

        public async Task DisposeAsync()
        {
            await Task.Run(
                () => MessageSink.OnMessage(
                    new DiagnosticMessage("AssemblyFixture disposed async.")));
        }


    }
}