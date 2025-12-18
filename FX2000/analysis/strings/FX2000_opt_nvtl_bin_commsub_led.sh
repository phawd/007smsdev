#!/bin/sh
cd /sys/aw9523-ioexp
NO_COLOR=0                                      
RED_COLOR=1                                     
GREEN_COLOR=2                                   
BLUE_COLOR=3                                    
YELLOW_COLOR=7                                  
PINK_COLOR=4                                    
WHITE_COLOR=6                                   
SEA_BLUE_COLOR=5                                
                                                
case $1 in                                      
        reset)                                  
                echo "no reset support"         
                ;;                              
        blue)                               
                echo $BLUE_COLOR > led_color   
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                            
                        echo 1 > led_blinking   
                        echo 0 > led_solid_on   
                fi                              
                ;;                              
        red)                                
                echo $RED_COLOR > led_color     
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                            
                        echo 1 > led_blinking   
                        echo 0 > led_solid_on   
                fi                              
                ;;              
	green)                            
                echo $GREEN_COLOR > led_color 
		echo $1 $2 
                if [ "$2" = "0" ]             
                then                          
                        echo 0 > led_blinking 
                        echo 1 > led_solid_on 
                else                          
                        echo 1 > led_blinking 
                        echo 0 > led_solid_on 
                fi                            
                ;;                            
        yellow)                             
                echo $YELLOW_COLOR > led_color  
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                            
                        echo 1 > led_blinking   
                        echo 0 > led_solid_on   
                fi                              
                ;;                              
        white)                              
                echo $WHITE_COLOR > led_color   
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                            
                        echo 1 > led_blinking   
                        echo 0 > led_solid_on   
                fi                              
                ;;                              
        pink)                               
                echo $PINK_COLOR > led_color    
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                            
                        echo 1 > led_blinking   
                        echo 0 > led_solid_on   
                fi                              
                ;;                              
        sea_blue)                           
                echo $SEA_BLUE_COLOR > led_color
		echo $1 $2 
                if [ "$2" = "0" ]               
                then                            
                        echo 0 > led_blinking   
                        echo 1 > led_solid_on   
                else                                                          
                        echo 1 > led_blinking                                 
                        echo 0 > led_solid_on                                 
                fi                                                            
                ;;                                                                                                                                  
        led_off)                                                                                                                                    
		echo $1  
                echo $NO_COLOR > led_color                                                                                                          
                ;;          
	*)                                                                    
                echo "Usage: $APP { reset | blue_led | red_led | green_led | yellow_led | white_led | pink_led | sea_blue_led | led_off }" >&2
                exit 1                                                                                                                              
                ;;      
esac                    
