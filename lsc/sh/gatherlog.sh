cd ~/data/log/log
cat ./* > ../total/all.txt
cd ../total
grep -E 'Analysing /home|add_con_time' all.txt > con_time.txt
grep -E 'Analysing /home|coverage' all.txt > coverage.txt
grep -E 'Analysing /home|execute_time' all.txt > exe_time.txt
grep -E 'Analysing /home|paths' all.txt > path.txt
grep -E 'Analysing /home|time_per' all.txt > per_time.txt
grep -E 'Analysing /home|solver_time' all.txt > sol_time.txt
grep -E 'Analysing /home|add_successor_time' all.txt > suc_time.txt

