// SPDX-License-Identifier: GPL-2.0
/*##############################################################################
#
#  acceleration_module.c: add extension of PP API
#  Copyright 2021, Inango Systems Ltd.
#  
#  Permission is hereby granted, free of charge, to any person obtaining a copy of
#  this software and associated documentation files (the "Software"), to deal in
#  the Software without restriction, including without limitation the rights to 
#  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#  the Software, and to permit persons to whom the Software is furnished to do so,
#  subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#  FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
##############################################################################*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Inango Systems Ltd.");
MODULE_DESCRIPTION("Extension to PP API");
MODULE_VERSION("0.01");

static int __init acceleration_module_init(void)
{
        printk(KERN_INFO "Acceleration module welcomes you!\n");
        return 0;
}

static void acceleration_module_exit(void)
{
        printk(KERN_INFO "Acceleration module is out\n");
}

module_init(acceleration_module_init);
module_exit(acceleration_module_exit);
