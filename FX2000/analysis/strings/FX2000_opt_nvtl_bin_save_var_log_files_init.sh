# INIT script used to start /opt/nvtl/bin/save_var_log_files.sh in background.
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
/opt/nvtl/bin/save_var_log_files.sh &
/opt/nvtl/bin/save_var_log_files_timer.sh &
