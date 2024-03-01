rule MALPEDIA_Win_Elise_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f217246a-45c9-5e4c-8fe4-ae9bb248bda8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elise"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.elise_auto.yar#L1-L163"
		license_url = "N/A"
		logic_hash = "4bacbe3f48e2ba0fdae2760e38d43f9e3c8b071aa93c58355438ff735f59b16b"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 0f8461010000 8d847eee040000 50 e8???????? 85c0 }
		$sequence_1 = { 8bd0 c1ea0b 0fafd7 3bf2 7312 b800080000 }
		$sequence_2 = { 8bcb 8dbe06050000 f3ab 8bc2 8bcb }
		$sequence_3 = { 33c9 33db 663b4e06 731a }
		$sequence_4 = { 8bcf e8???????? 8365f400 c1e004 0145fc 33f6 46 }
		$sequence_5 = { 894dec 8945f4 8dbeba0a0000 8bc3 8bce }
		$sequence_6 = { 7cf5 33c9 888f00010000 888f01010000 }
		$sequence_7 = { 8d3470 d3e0 0945f4 43 83fb04 72e1 8b45f4 }
		$sequence_8 = { 888f00010000 888f01010000 8bf7 8945f8 }
		$sequence_9 = { 8d3400 8b44240c 03c6 50 }
		$sequence_10 = { eb02 d1e8 4e 75f1 }
		$sequence_11 = { e8???????? 59 59 33c0 e9???????? 8b35???????? }
		$sequence_12 = { 42 0fb6fa 8a1c07 881c06 }
		$sequence_13 = { 897df4 8b7d08 03df 0fb63c06 }
		$sequence_14 = { 837d0c00 8a8800010000 8a9001010000 0f8e93000000 53 }
		$sequence_15 = { 301f ff45f8 8b7df8 3b7d0c 0f8c7bffffff 5f 5e }

	condition:
		7 of them and filesize <204800
}