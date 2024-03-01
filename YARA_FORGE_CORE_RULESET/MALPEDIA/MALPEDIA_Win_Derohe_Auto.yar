rule MALPEDIA_Win_Derohe_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "082c8bb6-5e90-542b-87a2-cd5536e22be3"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.derohe"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.derohe_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "3afbf42b0aba27d1df54ba6496f4a588ae2f7c7ec09fa3d922d168dfad26c783"
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
		$sequence_0 = { ffd0 8b542404 c60424e3 8b02 ffd0 8b542404 c6042405 }
		$sequence_1 = { ffd0 8b542404 c604247d 8b02 ffd0 8b542404 c60424df }
		$sequence_2 = { ffd0 8b542404 c60424a1 8b02 ffd0 8b542404 c60424e8 }
		$sequence_3 = { ffd0 8b442418 8b4c2414 8b542420 898a8c010000 8b0d???????? 85c9 }
		$sequence_4 = { ffd0 8b542404 c60424de 8b02 ffd0 8b542404 c60424b8 }
		$sequence_5 = { ffd0 8b542404 c60424cc 8b02 ffd0 8b542404 c6042462 }
		$sequence_6 = { e8???????? 8b44241c 8b4c2420 8b542424 8b5c2434 894b08 89530c }
		$sequence_7 = { ffd0 8b542404 c604247d 8b02 ffd0 8b542404 c60424a4 }
		$sequence_8 = { ffd2 8b442404 83c0fa 83f801 0f869e000000 90 8b4c242c }
		$sequence_9 = { ffd0 8b542404 c60424e0 8b02 ffd0 8b542404 c6042407 }

	condition:
		7 of them and filesize <35788800
}