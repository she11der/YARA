import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Scan_BAT
{
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "836e0618-93c7-5519-bbc4-705ff5c2e127"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1196-L1214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
		logic_hash = "eed941d2ad5d33d7224504b08d2104d4043fab7a2ff027fc54cd1afd42e32549"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f %%a in (host.txt) do (" ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii

	condition:
		5 of them
}
