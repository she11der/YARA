rule SIGNATURE_BASE_CN_Tools_Vnclink : FILE
{
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "270dc14c-ac8f-58c2-b4ac-c10981e20a07"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1876-L1891"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
		logic_hash = "21328e2a871dfcfda47991a1f1e897efd27471420d644c09a94004cf5b0f9869"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <580KB and 2 of them
}
