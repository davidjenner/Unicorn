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

# Print network information
echo "Network Information:"
echo "--------------------"
ifconfig
echo ""

location=$(dig +short -x $ip)


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



printf '\n************\n* Social Media Links *\n************\n\n'


echo "Searching for social media links on the website..."
social_links=$(curl -s $url | grep -oE '(https?:\/\/(www\.)?(facebook|twitter|instagram|linkedin)\.com\/\S+)')
if [[ -n "$social_links" ]]; then
    echo "The following social media links were found on the website:"
    echo "$social_links"
else
    echo "No social media links were found on the website."
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


printf '\n************\n* WP Scan plugins Plugins 1 *\n************\n\n'

# Get the URL from the command line argument
url=$1

# Run WPScan to get plugin details
wpscan_result=$(wpscan --url $url --plugins-detection mixed --no-banner --disable-tls-checks --random-agent)

# Output the results
echo "$wpscan_result"


printf '\n************\n* Email *\n************\n\n'



echo "Searching for email addresses on $url..."

emails=$(curl -s $url | grep -E -o "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

if [[ -n "$emails" ]]; then
    echo "The following email addresses were found on the website:"
    echo "$emails"
else
    echo "No email addresses were found on the website."
fi


printf '\n************\n* Broken Pages and Images *\n************\n\n'



# Get list of all pages on website
echo "Getting list of all pages on website..."
pages=$(wget --spider -r -nd "$url" 2>&1 | grep '^--' | awk '{print $3}' | grep -v '\.\(css\|js\|png\|gif\|jpg\)$')

# Create array to store pages with errors
error_pages=()

# Loop through pages and check for errors
for page in $pages; do
    echo "Checking page: $page"
    # Use curl to check for HTTP errors
    if ! curl --output /dev/null --silent --head --fail "$page"; then
        echo "Page $page returned an error."
        error_pages+=("$page")
    fi
done

# Print out any pages with errors
if [ ${#error_pages[@]} -eq 0 ]; then
    echo "No errors found on any pages."
else
    echo "Errors found on the following pages:"
    printf '%s\n' "${error_pages[@]}"
fi

# Get list of all images on website
echo "Getting list of all images on website..."
images=$(wget --spider -r -nd "$url" 2>&1 | grep '^--' | awk '{print $3}' | grep -E '.(png|jpg|jpeg|gif)$')

# Create array to store images with errors
error_images=()

# Loop through images and check for errors
for image in $images; do
    echo "Checking image: $image"
    # Use curl to check for HTTP errors
    if ! curl --output /dev/null --silent --head --fail "$image"; then
        echo "Image $image returned an error."
        error_images+=("$image")
    fi
done

# Print out any images with errors
if [ ${#error_images[@]} -eq 0 ]; then
    echo "No errors found on any images."
else
    echo "Errors found on the following images:"
    printf '%s\n' "${error_images[@]}"
fi

echo "Scan complete."


printf '\n************\n* Check for vulnerabilities *\n************\n\n'


if [ "$#" -ne 1 ]; then
    echo "Usage: ./web-checker.sh <website>"
    exit
fi

website=$1


# run nikto vulnerability scan
echo "Running nikto vulnerability scan on $website..."
nikto -h $website -output nikto_scan.txt -Format htm

# extract vulnerabilities from nikto scan results
echo "Extracting vulnerabilities from Nikto scan results..."
grep "^[+]*[0-9]* vulnerabilities" nikto_scan.txt | sed -e 's/\(.*\)\([0-9]\+ vulnerabilities\)\(.*\)/\2/g' > nikto_vulns.txt

# check if any vulnerabilities were found
if [ ! -s nikto_vulns.txt ]; then
    echo "No vulnerabilities were found on $website."
else
    echo "The following vulnerabilities were found on $website:"
fi
