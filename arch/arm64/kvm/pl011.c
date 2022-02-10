// SPDX-License-Identifier: GPL-2.0
#include <asm/io.h>
#include <asm/kvm_mmu.h>

#include <linux/clk.h>
#include <linux/amba/bus.h>

#include <kvm/pl011.h>

/*
 * Base address of the UART to commandeer
 * For example pl011.hyp_uart=0x9000000
 */
static u64 cmdline_uart_base;

static int __init kvm_arm_pl011_cmdline(char *str)
{
	int ret = kstrtou64(str, 0, &cmdline_uart_base);

        return ret;
}
early_param("pl011.hyp_uart", kvm_arm_pl011_cmdline);

static int kvm_arm_pl011_probe(struct amba_device *adev,
			       const struct amba_id *id)
{
	int ret;
	int brd;
	struct clk *clk;
	void __iomem *base;
	struct resource *res;
	unsigned long uartclk;
	struct kvm_arm_pl011_device *hyp_dev;
	unsigned long baud = 115200; /* probably */

	res = &adev->res;
	if (!cmdline_uart_base || cmdline_uart_base != res->start)
		return -ENODEV;

	clk = devm_clk_get(&adev->dev, NULL);
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	base = devm_ioremap_resource(&adev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	hyp_dev = (void *)__get_free_page(GFP_KERNEL);
	if (!hyp_dev)
		return -ENOMEM;

	ret = clk_enable(clk);
	if (ret)
		return ret;

	uartclk = clk_get_rate(clk);

	brd = uartclk * 4 / baud;
	writel(brd & 0x3f, base + PL011_FBRD);
	writel(brd >> 6, base + PL011_IBRD);

	/* Clear errors */
	writel(0xf, base + PL011_ECR);

	/* 8-bit, no parity, 1 stop bit, FIFO enabled */
	writel((3 << 5) | (1 << 4), base + PL011_LCR_H);
	/* UARTEN, TXE */
	writel((1 << 8) | (1 << 0), base + PL011_CR);

	hyp_dev->mmio_addr = res->start;
	hyp_dev->mmio_size = resource_size(res);
	kvm_hyp_arm_pl011_device = kern_hyp_va(hyp_dev);

	dev_info(&adev->dev, "probed\n");
	return 0;
}

static const struct of_device_id pl011_of_match[] = {
	{ .compatible = "arm,pl011", },
	{ },
};

static const struct amba_id pl011_ids[] = {
	{
		.id	= 0x00041011,
		.mask	= 0x000fffff,
	},
	{ 0, 0 },
};

static struct amba_driver kvm_arm_pl011_driver = {
	.drv = {
		.name = "kvm-pl011",
		.of_match_table = pl011_of_match,
	},
	.id_table	= pl011_ids,
	.probe		= kvm_arm_pl011_probe,
};

static int __init kvm_arm_pl011_init(void)
{
	return amba_driver_register(&kvm_arm_pl011_driver);
}

arch_initcall(kvm_arm_pl011_init);
