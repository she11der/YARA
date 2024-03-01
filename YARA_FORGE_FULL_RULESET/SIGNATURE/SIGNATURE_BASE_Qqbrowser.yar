rule SIGNATURE_BASE_Qqbrowser : FILE
{
	meta:
		description = "Not malware but suspicious browser - file QQBrowser.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "457507c5-0411-5d72-891b-ae3e428ea2d6"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_fireball.yar#L53-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "525d134f57aaa314bcf0676678264e518edb785970478cb31a8fb6f1c8c92263"
		score = 50
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"

	strings:
		$s1 = "TerminateProcessWithoutDump" fullword ascii
		$s2 = ".Downloader.dll" fullword wide
		$s3 = "Software\\Chromium\\BrowserCrashDumpAttempts" fullword wide
		$s4 = "QQBrowser_Broker.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
