import "pe"

rule SIGNATURE_BASE_Sig_238_2323
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "445f6a49-51e6-5eb8-ae08-e5989aafb6c4"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2180-L2198"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
		logic_hash = "1278c53f64a0ba7f3f6a728237eac6808b260ad36551923276bfba9b36586870"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii

	condition:
		all of them
}
