namespace KeyVaultCA
{
    public class CsrConfiguration
    {
        public bool IsRootCA { get; set; } = false;

        public bool IsIntermediateCA { get; set; } = false;

        public string Subject { get; set; }

        public string PathToCsr { get; set; }

        public string OutputFileName { get; set; }
    }
}
