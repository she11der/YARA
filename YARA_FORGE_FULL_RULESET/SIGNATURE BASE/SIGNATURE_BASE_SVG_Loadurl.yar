rule SIGNATURE_BASE_SVG_Loadurl : FILE
{
	meta:
		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth (Nextron Systems)"
		id = "c3d4c95f-ef8b-52ff-9cf9-d66d9b99a490"
		date = "2015-05-24"
		modified = "2023-12-05"
		reference = "http://goo.gl/psjCCc"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_cryptowall_svg.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d9e40694e2d0099495289a2074e266bace9b0d9d776391020a1527eaabd2a395"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"

	strings:
		$s1 = "</svg>" nocase
		$s2 = "<script>" nocase
		$s3 = "location.href='http" nocase

	condition:
		all of ($s*) and filesize <600
}
