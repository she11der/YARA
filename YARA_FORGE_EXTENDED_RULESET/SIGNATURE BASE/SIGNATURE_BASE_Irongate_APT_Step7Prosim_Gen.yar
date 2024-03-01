rule SIGNATURE_BASE_Irongate_APT_Step7Prosim_Gen : FILE
{
	meta:
		description = "Detects IronGate APT Malware - Step7ProSim DLL"
		author = "Florian Roth (Nextron Systems)"
		id = "a73cf9e2-c24f-5553-92e2-3a1a882a4a06"
		date = "2016-06-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/Mr6M2J"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_irongate.yar#L10-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "aab41ada32a8186f958baccad08b60ac1ab686f7561d4dd4471a1e88ddd53730"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0539af1a0cc7f231af8f135920a990321529479f6534c3b64e571d490e1514c3"
		hash2 = "fa8400422f3161206814590768fc1a27cf6420fc5d322d52e82899ac9f49e14f"
		hash3 = "5ab1672b15de9bda84298e0bb226265af09b70a9f0b26d6dfb7bdd6cbaed192d"

	strings:
		$x1 = "\\obj\\Release\\Step7ProSim.pdb" ascii
		$s1 = "Step7ProSim.Interfaces" fullword ascii
		$s2 = "payloadExecutionTimeInMilliSeconds" fullword ascii
		$s3 = "PackagingModule.Step7ProSim.dll" fullword wide
		$s4 = "<KillProcess>b__0" fullword ascii
		$s5 = "newDllFilename" fullword ascii
		$s6 = "PackagingModule.exe" fullword wide
		$s7 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" fullword ascii
		$s8 = "RunPlcSim" fullword ascii
		$s9 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" fullword ascii
		$s10 = "InstallProxy" fullword ascii
		$s11 = "DllProxyInstaller" fullword ascii
		$s12 = "FindFileInDrive" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and ($x1 or 3 of ($s*))) or (6 of them )
}
