rule SECUINFRA_SUS_Unsigned_APPX_MSIX_Manifest_Feb23
{
	meta:
		description = "Detects suspicious Microsoft Windows APPX/MSIX Installer Manifests"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "f24f7e03-3cc5-5214-b6d2-205b69898636"
		date = "2023-02-01"
		modified = "2023-02-07"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/SUS_Unsigned_APPX_MSIX_Manifest_Feb23.yar#L1-L25"
		license_url = "N/A"
		logic_hash = "4e3de25fdad9d76cefbb191424a739368b521c4f234656c397f4122debe749fa"
		score = 65
		quality = 70
		tags = ""
		tlp = "CLEAR"

	strings:
		$xlmns = "http://schemas.microsoft.com/appx/manifest/"
		$identity = "OID.2.25.311729368913984317654407730594956997722=1"
		$s_entrypoint = "EntryPoint=\"Windows.FullTrustApplication\""
		$s_capability = "runFullTrust"
		$s_peExt = ".exe"

	condition:
		uint32be(0x0)==0x3C3F786D and $xlmns and $identity and 2 of ($s*)
}