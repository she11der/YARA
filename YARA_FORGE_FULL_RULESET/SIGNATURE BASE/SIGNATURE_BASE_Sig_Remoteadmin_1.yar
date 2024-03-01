import "pe"

rule SIGNATURE_BASE_Sig_Remoteadmin_1 : FILE
{
	meta:
		description = "Detects strings from well-known APT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "da55084c-ec1f-5800-a614-189dce7b5820"
		date = "2017-12-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4106-L4120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "81912bbfc1f6ac3ec7c54fc935b9ed531c97ad509cf2c096a19e638836cd0baf"
		score = 45
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$ = "Radmin, Remote Administrator" wide
		$ = "Radmin 3.0" wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}
