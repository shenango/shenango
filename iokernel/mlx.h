#pragma once

#ifdef MLX4

#include <mlx4_custom.h>
#define MLX
#define mlx_reg_mem mlx4_manual_reg_mr
#define mlx_dereg_mem mlx4_manual_dereg_mr


#elif defined(MLX5)
#include <mlx5_custom.h>
#define MLX
#define mlx_reg_mem mlx5_manual_reg_mr
#define mlx_dereg_mem mlx5_manual_dereg_mr

#endif
