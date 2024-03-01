rule MALPEDIA_Win_Abaddon_Pos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8a8bfe7b-07a3-507a-8985-62178b8d7d5d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abaddon_pos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.abaddon_pos_auto.yar#L1-L170"
		license_url = "N/A"
		logic_hash = "e2d8547af0d263d117f46abc9755b5a7e9f77ec4346ade26de1285350cf4f083"
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
		$sequence_0 = { 7402 eb27 8b8600010000 03860c010000 89867c010000 8b8684010000 }
		$sequence_1 = { ba00000000 eb05 ba01000000 0186ac010000 }
		$sequence_2 = { 80beb801000001 751b 80fa30 7205 80fa39 7605 80fa20 }
		$sequence_3 = { 41 89c0 49 c7c100000000 ff15???????? 48 83c420 }
		$sequence_4 = { 48 8986d0050000 48 83ec20 48 c7c100000000 }
		$sequence_5 = { 89d8 69c080000000 3d002d0000 7602 eb22 }
		$sequence_6 = { 7318 807c1e2c41 720c 807c1e2c5a }
		$sequence_7 = { 81bea001000000dc0500 740c 81bea001000000d60600 7508 6a05 ff15???????? 8b86a0010000 }
		$sequence_8 = { 31c9 31d2 80beb401000001 7505 }
		$sequence_9 = { ffc3 ebd1 48 31db }
		$sequence_10 = { 8986b0050000 48 83ec20 48 8b8eb0050000 48 }
		$sequence_11 = { 0504d00700 48 8986c8050000 48 0504d00700 48 8986d0050000 }
		$sequence_12 = { 83f800 7502 ebe4 50 ff15???????? 6a00 6a00 }
		$sequence_13 = { 83c000 48 8b9eb8050000 48 8918 48 }
		$sequence_14 = { 0500040000 3b19 730f 311418 }
		$sequence_15 = { 720b 803939 7706 fe86a8010000 }

	condition:
		7 of them and filesize <40960
}
