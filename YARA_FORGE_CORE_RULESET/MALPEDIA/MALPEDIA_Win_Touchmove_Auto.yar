rule MALPEDIA_Win_Touchmove_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a88e9c25-4116-5e49-8a2c-fef3336f0802"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.touchmove"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.touchmove_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "519a7e3bd048a6a0769391087a62b1ec389f7202cc576a740e9eb0fb3d43844d"
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
		$sequence_0 = { 41b800040000 488d8c2452010000 e8???????? 4c8d442448 488d152df90000 }
		$sequence_1 = { 488d157af70000 488d8d90000000 e8???????? 4c8d8590000000 33d2 33c9 }
		$sequence_2 = { 7528 48833d????????00 741e 488d0d499f0000 e8???????? 85c0 }
		$sequence_3 = { 41b8ee000000 488d8d92430000 e8???????? c6858044000000 33d2 41b8ff000000 488d8d81440000 }
		$sequence_4 = { ff15???????? 488d442450 4889442420 458bce 4533c0 488d9580410000 48c7c102000080 }
		$sequence_5 = { 0f8514010000 4c8d2d36cd0000 41b804010000 668935???????? 498bd5 ff15???????? 418d7c24e7 }
		$sequence_6 = { 48833d????????00 0f844d040000 48833d????????00 0f843f040000 }
		$sequence_7 = { 833d????????00 7505 e8???????? 488d3d40e00000 41b804010000 }
		$sequence_8 = { 488bfb 488bf3 48c1fe05 4c8d25bebd0000 83e71f 486bff58 }
		$sequence_9 = { 8bc8 e8???????? ebc9 488bcb 488bc3 488d1597e40000 48c1f805 }

	condition:
		7 of them and filesize <224256
}
