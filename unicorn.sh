#!/bin/bash

cat ascii_art.txt

echo "Enter website URL (e.g. https://example.com): "
read url

echo ""
echo "Scanning website $url..."

# Check if website is online
echo "Checking if website is online..."
if curl --output /dev/null --silent --head --fail "$url"; then
    echo "Website is online."
else
    echo "Website is offline. Exiting program."
    exit 1
fi

# Check if the website is a WordPress site
echo "Checking if $url is a WordPress site..."
wp_check=$(curl -s $url/wp-includes/version.php | grep -i "wp_version\|doctype html")
if [[ $wp_check == *"wp_version"* ]]; then
    echo "$url is a WordPress site."
    is_wordpress=true
else
    echo "$url is not a WordPress site."
    is_wordpress=false
fi

server=$(curl -I $url | grep 'Server:' | awk '{print $2}')
ip=$(curl -s $url | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -n 1)
location=$(dig -x $ip +short)
whois_data=$(whois $url)
software=$(curl -s -L $url | grep -iE 'server|powered-by' | sed 's/<[^>]*>//g' | tr -s ' ')

printf '\n************\n* Your IP Address *\n************\n\n'

ip addr show | grep inet | awk '$1=="inet" {print $2}'

my_ip=$(curl -s ifconfig.me)

ip=$(curl -s https://whatismyipaddress.com/ | grep -oP 'Your IP Address[^<]*\K[\d.]+')

echo "Your IP address is: $ip"


printf '\n************\n* HTTP Headers *\n************\n\n'


headers=$(curl -s -I $url)

echo "$headers"

printf '\n************\n* SERVER INFORMATION *\n************\n\n'

# Type of server website is running on
server=$(curl -I $url | grep 'Server:' | awk '{print $2}')

# Get server IP address
ip=$(curl -s $url | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -n 1)

# Use dig to get location information
location=$(dig -x $ip +short)

# Get software information
software=$(curl -s -L $url | grep -iE 'server|powered-by' | sed 's/<[^>]*>//g' | tr -s ' ')

# Print server information
echo "Server Information for $url:"
echo "-------------------"
echo "Type of server: $server"
echo "IP address: $ip"
echo "Location: $location"
echo "Software: $software"



printf '\n************\n* DNS Details inc Domain Registrar *\n************\n\n'


# Get details of the DNS registrar
registrar=$(whois $url | awk -F': ' '/Registrar:/ {print $2}')
if [[ -n "$registrar" ]]; then
    echo "The DNS registrar for $url is $registrar."
else
    echo "Unable to retrieve DNS registrar for $url."
fi

# Domain name registration Date
echo "Checking domain registration information..."
reg_date=$(whois $url | grep -i "creation date" | awk -F: '{print $2}')
if [[ -n "$reg_date" ]]; then
    echo "The domain was registered on: $reg_date"
else
    echo "Unable to retrieve domain registration information."
fi

# Use dig to get the DNS records for the website
echo "Getting DNS records for $url..."
dns=$(dig $url any +noall +answer)

if [[ -n "$dns" ]]; then
    echo "DNS records for $url:"
    echo "$dns"
else
    echo "Unable to get DNS records for $url."
fi



printf '\n************\n* Who.is information *\n************\n\n'

whois $url | grep -Ei "Registrant|Admin|Tech|Name Server|Organization" | grep -vE "Private|Data|Domain|Whois|Registrar"




printf '\n************\n* SSL/TLS Certificate Details *\n************\n\n'

openssl s_client -connect $url:443 < /dev/null 2>/dev/null | openssl x509 -noout -issuer -dates -subject

printf '\n************\n* Page Speed and Performance Metrics *\n************\n\n'

curl -o /dev/null -s -w "Connect time: %{time_connect}\nStart transfer time: %{time_starttransfer}\nTotal time: %{time_total}\nHTTP response code: %{http_code}\nSize: %{size_download} bytes\n" $url


echo -e "\n************\n* Server-side Scripting Languages *\n************\n\n"

# Check if PHP is installed and get its version
if [[ $(command -v php) ]]; then
    php_version=$(php -v | awk '/^PHP/ {print $2}')
    echo "PHP $php_version is installed."
else
    echo "PHP is not installed."
fi


# Check if ASP.NET is installed and get its version
if [[ $(command -v dotnet) ]]; then
    dotnet_version=$(dotnet --version)
    echo "ASP.NET $dotnet_version is installed."
else
    echo "ASP.NET is not installed."
fi



printf '\n************\n* WordPress Word Count *\n************\n\n'


echo "Counting number of words and pages on the website..."

# Get the sitemap.xml file
sitemap_url="$url/sitemap.xml"
sitemap=$(curl -s $sitemap_url)

# Count the number of pages in the sitemap
page_count=$(echo $sitemap | grep -o '<loc>' | wc -l)

# Get the word count of all pages on the website
word_count=$(curl -s -L $url | wc -w)
for page_url in $(echo $sitemap | grep -o '<loc>.*</loc>' | sed 's/<loc>//;s/<\/loc>//')
do
    word_count=$(expr $word_count + $(curl -s -L $page_url | wc -w))
done

if [[ -n "$word_count" && -n "$page_count" ]]; then
    echo "The website has $word_count words and $page_count pages."
else
    echo "Unable to retrieve word and page count for the website."
fi



printf '\n************\n* Developer comments in the code *\n************\n\n'

# Scan for comments
echo "Scanning for comments in code..."
comments=$(curl -s $url | grep -o '<!--.*-->' | sed 's/<!--//;s/-->//')
if [[ -n "$comments" ]]; then
    echo "Comments found in code:"
    echo "$comments"
else
    echo "No comments found in code."
fi



printf '\n************\n* WordPress Version *\n************\n\n'


# Get WordPress version
echo "Checking WordPress version..."
wp_version=$(curl -s -L $url | grep -i -m 1 -o -E 'wordpress [0-9.]+' | cut -d' ' -f2)
if [[ -n "$wp_version" ]]; then
    echo "WordPress version detected: $wp_version"
    
    # Get latest WordPress version
    echo "Checking latest WordPress version..."
    latest_version=$(curl -s https://wordpress.org/download/ | grep -i -m 1 -o -E 'wordpress [0-9.]+' | cut -d' ' -f2)
    
    # Compare WordPress versions
    if [[ "$wp_version" == "$latest_version" ]]; then
        echo "WordPress is up to date."
    else
        echo "WordPress is not up to date. The latest version is $latest_version."
    fi
else
    echo "Unable to detect WordPress version."
fi



printf '\n************\n* WordPress Plugins 1 *\n************\n\n'



# Get list of installed plugins
wp_plugins=$(curl -s -L $url/wp-admin/plugins.php | grep -o -E '<span class="plugin-name">([^<]*)</span>' | cut -d'>' -f2 | cut -d'<' -f1)

    # Check for WordPress plugins
    echo "Checking WordPress plugins..."
    wp_plugins=$(curl -s -L $url | grep -i -o 'wp-content/plugins/[^/"]*' | cut -d'/' -f 3 | sort | uniq)
    if [[ -n "$wp_plugins" ]]; then
        echo "WordPress plugins detected:"
        for plugin in $wp_plugins; do
            echo -n "$plugin "
            plugin_latest_version=$(curl -s "https://api.wordpress.org/plugins/info/1.0/$plugin.json" | jq -r '.version')
            if [[ "$plugin_latest_version" == "null" ]]; then
                echo "Unable to determine latest version of $plugin."
            elif [[ "$plugin_latest_version" == "$(echo -e "$plugin_latest_version\n$wp_version" | sort -V | head -n1)" ]]; then
                echo "Latest version of $plugin ($plugin_latest_version) is installed."
            else
                echo "Newer version of $plugin ($plugin_latest_version) is available."
            fi
        done
    else
        echo "No WordPress plugins detected."
    fi

# Get cookie information
echo -e "\n************\n* Website Cookies *\n************\n\n"
cmd="curl -I -s $url | grep 'Set-Cookie:'"
result=$(eval "$cmd")
if [ -z "$result" ]; then
    echo "No cookies found on the website."
else
    echo "Cookies found on the website:"
    echo "$result"
fi

# Get page speed and performance metrics
echo -e "\n************\n* Page Speed and Performance Metrics *\n************\n\n"
cmd="curl -o /dev/null -s -w \"Connect time: %{time_connect}\nStart transfer time: %{time_starttransfer}\nTotal time: %{time_total}\nHTTP response code: %{http_code}\nSize: %{size_download} bytes\n\" $url"
result=$(eval "$cmd")
echo "$result"

echo -e "\n************\n* WordPress Usernames *\n************\n\n"
wpscan --url $url --enumerate u

# Check if wpscan is installed
if ! command -v wpscan &> /dev/null
then
    echo "wpscan is not installed. Please install wpscan before running this script."
    echo "To install wpscan, run the following command:"
    echo "sudo gem install wpscan"
    exit 1
fi

# Run wpscan if the website is a WordPress site
# if [[ $is_wordpress == true ]]; then
    echo -e "\n************\n* WordPress Passwords *\n************\n\n"
    if [[ $(command -v wpscan) ]]; then
        mkfifo wpscan_pipe
        curl -s https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt > wpscan_pipe &
        wpscan --url $url --usernames admin --passwords wpscan_pipe --threads 50 --wp-content-dir wp-content --max-threads 50
        rm wpscan_pipe
    else
        echo "wpscan is not installed. Install it from https://wpscan.com/wordpress-security-scanner."
    fi
fi
