rule SIGNATURE_BASE_Apt_Regin_Hopscotch : FILE
{
	meta:
		description = "Rule to detect Regin's Hopscotch module"
		author = "Kaspersky Lab"
		id = "907042ba-8e64-5ca7-9a83-70c28af1ab99"
		date = "2015-01-22"
		date = "2023-01-27"
		modified = "2023-12-15"
		reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_regin_fiveeyes.yar#L320-L341"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6c34031d7a5fc2b091b623981a8ae61c"
		logic_hash = "33b5fa61aaa802a60f3d42d59eb474222841a8a557b06b23a9e325e922e2cec1"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = "AuthenticateNetUseIpc"
		$a2 = "Failed to authenticate to"
		$a3 = "Failed to disconnect from"
		$a4 = "%S\\ipc$" wide
		$a5 = "Not deleting..."
		$a6 = "CopyServiceToRemoteMachine"
		$a7 = "DH Exchange failed"
		$a8 = "ConnectToNamedPipes"

	condition:
		uint16(0)==0x5A4D and all of ($a*)
}
