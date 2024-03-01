rule MALPEDIA_Win_Woodyrat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ce77dd1e-7a7f-526f-b26a-f53840a84ce1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woodyrat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.woodyrat_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "f0e3660df6e09cfccf9351d956d7545670538be69e20bfd57639d1e54207defb"
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
		$sequence_0 = { 8b75ec 8985a4ebffff ffb5bcebffff e8???????? 8b7de4 83c404 837de800 }
		$sequence_1 = { 8d4e4c 54 6a00 e8???????? 8bc8 e8???????? 8d4dd8 }
		$sequence_2 = { 8d4710 50 8d45cc 50 e8???????? 84c0 7403 }
		$sequence_3 = { e8???????? c645fc03 8b55cc 83fa10 722c 8b4db8 42 }
		$sequence_4 = { 8b4328 8bd8 3bfb 742d 8b0f 8b01 ff5008 }
		$sequence_5 = { 8bc8 83781410 7202 8b08 83781004 753b 8b01 }
		$sequence_6 = { 83c408 8d4508 6a00 84db 7428 837d1c08 6800000002 }
		$sequence_7 = { 50 e8???????? 8b7d80 83c404 e9???????? c645fc00 }
		$sequence_8 = { 7607 be55555515 eb07 03f1 3bf2 0f42f2 }
		$sequence_9 = { 745d 40 50 e8???????? 8bf0 8b45c8 40 }

	condition:
		7 of them and filesize <785408
}
