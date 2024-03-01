import "pe"

rule SIGNATURE_BASE_Hvs_APT37_Webshell_Controllers_Asp : FILE
{
	meta:
		description = "Webshell named controllers.asp or inc-basket-offer.asp used by APT37"
		author = "Moritz Oettle"
		id = "82370415-30f4-514d-8806-e2daced96f07"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_lazarus_dec20.yar#L140-L218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "829462fc6d84aae04a962dfc919d0a392265fbf255eab399980d2b021e385517"
		logic_hash = "a6e53e99f7500683d3b62a7630cecb53ee6c13b335cbf9912366675db964aefe"
		score = 75
		quality = 28
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@Language=VBScript.Encode" ascii
		$x1 = { 64 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x2 = { 64 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x3 = { 64 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x4 = { 64 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x5 = { 64 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x6 = { 64 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x7 = { 64 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x8 = { 64 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x9 = { 64 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x10 = { 64 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x11 = { 64 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x12 = { 64 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x13 = { 64 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x14 = { 64 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x15 = { 64 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x16 = { 64 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x17 = { 64 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x18 = { 64 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x19 = { 64 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x20 = { 64 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x21 = { 64 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x22 = { 64 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x23 = { 64 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x24 = { 64 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x25 = { 64 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x26 = { 6A 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x27 = { 6A 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x28 = { 6A 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x29 = { 6A 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x30 = { 6A 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x31 = { 6A 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x32 = { 6A 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x33 = { 6A 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x34 = { 64 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x35 = { 6A 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x36 = { 6A 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x37 = { 6A 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x38 = { 6A 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x39 = { 6A 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x40 = { 6A 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x41 = { 6A 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x42 = { 6A 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x43 = { 6A 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x44 = { 6A 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x45 = { 64 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x46 = { 6A 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x47 = { 6A 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x48 = { 6A 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x49 = { 6A 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x50 = { 6A 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x51 = { 6A 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x52 = { 6A 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x53 = { 6A 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x54 = { 6A 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x55 = { 6A 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x56 = { 64 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x57 = { 6A 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x58 = { 6A 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x59 = { 6A 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x60 = { 6A 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x61 = { 64 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x62 = { 64 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x63 = { 64 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
		$x64 = { 64 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }

	condition:
		filesize >50KB and filesize <200KB and ($s0 and 1 of ($x*))
}
