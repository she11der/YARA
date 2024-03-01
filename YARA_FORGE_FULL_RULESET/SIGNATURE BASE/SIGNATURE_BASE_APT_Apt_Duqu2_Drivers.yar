rule SIGNATURE_BASE_APT_Apt_Duqu2_Drivers : FILE
{
	meta:
		description = "Rule to detect Duqu 2.0 drivers"
		author = "Kaspersky Lab"
		id = "714d5151-9f80-582e-a628-1de9d83a072d"
		date = "2015-06-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_kaspersky_duqu2.yar#L40-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "023a51408f86814a8f810d0f89b185aca07dd60a1abb6de47f86ad8eeda4c4c4"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = "\\DosDevices\\port_optimizer" wide nocase
		$a2 = "romanian.antihacker"
		$a3 = "PortOptimizerTermSrv" wide
		$a4 = "ugly.gorilla1"
		$b1 = "NdisIMCopySendCompletePerPacketInfo"
		$b2 = "NdisReEnumerateProtocolBindings"
		$b3 = "NdisOpenProtocolConfiguration"

	condition:
		uint16(0)==0x5A4D and ( any of ($a*)) and (2 of ($b*)) and filesize <100000
}
