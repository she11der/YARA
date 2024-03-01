rule SECUINFRA_SUS_Unsigned_APPX_MSIX_Installer_Feb23
{
	meta:
		description = "Detects suspicious, unsigned Microsoft Windows APPX/MSIX Installer Packages"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "beaf08a8-a1c3-5d9c-b7cb-81a49c5bc2ec"
		date = "2023-02-01"
		modified = "2023-02-07"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/SUS_Unsigned_APPX_MSIX_Installer_Feb23.yar#L1-L22"
		license_url = "N/A"
		logic_hash = "ad3f0545b2fe285adf67f053c8b422126a1bdff1b6835631280442495d975d16"
		score = 50
		quality = 30
		tags = ""
		tlp = "CLEAR"

	strings:
		$s_manifest = "AppxManifest.xml"
		$s_block = "AppxBlockMap.xml"
		$s_peExt = ".exe"
		$sig = "AppxSignature.p7x"

	condition:
		uint16be(0x0)==0x504B and 2 of ($s*) and not $sig
}
