rule SIGNATURE_BASE_Hytop_Devpack_Upload
{
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "43054993-b0dd-5d2e-9890-db1f47759be5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8047-L8058"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b09852bda534627949f0259828c967de"
		logic_hash = "312020a72a37adb0111ac6d61810c8e476be39dc6456e80e83cd6a680e8ea051"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<!-- PageUpload Below -->"

	condition:
		all of them
}
