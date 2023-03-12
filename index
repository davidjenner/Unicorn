#!/bin/bash

cat ascii_art.txt

# for when used with website form
# input=$1

# echo "You entered: $input"
# echo "Result: $(($input * 2))"

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

echo "The website $url is running on the server: $server"
echo "The server's IP address is: $ip"
echo "The server is located in: $location"
echo "DNS details for $url:"
echo "$whois_data"
echo "The website is running the following software:"
echo "$software"
echo "Getting details of the IP address..."
whois $ip_address

echo "Getting hosting company for $ip_address..."
hosting_company=$(whois $ip_address | grep -i 'OrgName\|netname' | awk -F':' '{print $2}' | tr -d ' ')

if [[ -n "$hosting_company" ]]; then
    echo "The hosting company for $ip_address is $hosting_company."
else
    echo "Unable to retrieve hosting company for $ip_address."
fi

echo "Checking domain registration information..."
reg_date=$(whois $url | grep -i "creation date" | awk -F: '{print $2}')
if [[ -n "$reg_date" ]]; then
    echo "The domain was registered on: $reg_date"
else
    echo "Unable to retrieve domain registration information."
fi

# Get details of the IP address
ip_address=$(dig +short $url | tail -n1)
if [[ -n "$ip_address" ]]; then
    echo "The IP address of $url is $ip_address."
else
    echo "Unable to retrieve IP address of $url."
fi

# Get IP address and country code
ip=$(dig +short $domain)
country=$(whois $ip | awk -F':' '/^Country/ {print $2}' | tr -d ' ')

if [[ -n "$ip" ]]; then
  echo "IP address: $ip"
  echo "Country code: $country"
else
  echo "Unable to retrieve IP address and country code."
fi


# Get details of the DNS registrar
registrar=$(whois $url | awk -F': ' '/Registrar:/ {print $2}')
if [[ -n "$registrar" ]]; then
    echo "The DNS registrar for $url is $registrar."
else
    echo "Unable to retrieve DNS registrar for $url."
fi


echo "Creating wordlist from the website content..."
wordlist=$(curl -s -L $url | grep -oE '\b[[:alpha:]]{5,10}\b' | sort -u)

if [[ -n "$wordlist" ]]; then
    echo "$wordlist" > wordlist.txt
    echo "Wordlist saved to wordlist.txt."
else
    echo "No words were found on the website."
fi

echo "Searching for email addresses on $url..."

emails=$(curl -s $url | grep -E -o "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

if [[ -n "$emails" ]]; then
    echo "The following email addresses were found on the website:"
    echo "$emails"
    echo "$emails" > email_addresses.txt
    echo "Email addresses saved to email_addresses.txt."
else
    echo "No email addresses were found on the website."
fi

echo "Searching for social media links on the website..."
social_links=$(curl -s $url | grep -oE 'https?://[^/]+/(?:\w+/)*\w+')
if [[ -n "$social_links" ]]; then
    echo "The following social media links were found on the website:"
    echo "$social_links"
else
    echo "No social media links were found on the website."
fi

echo "Counting number of words and pages on the website..."
word_count=$(curl -s -L $url | wc -w)
page_count=$(curl -s -L $url | grep -c '</html>')
if [[ -n "$word_count" && -n "$page_count" ]]; then
    echo "The website has $word_count words and $page_count pages."
else
    echo "Unable to retrieve word and page count for the website."
fi

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

# Get latest version of WordPress
latest_version=$(curl -s https://api.wordpress.org/core/version-check/1.7/ | jq -r '.offers[0].current')

# Compare WordPress version with latest version
if [[ "$wp_version" == "$latest_version" ]]; then
    echo "WordPress is up to date."
else
    echo "WordPress is not up to date. The latest version is $latest_version."
fi

echo "Checking WordPress plugins..."

# Get list of installed plugins
wp_plugins=$(curl -s -L $url/wp-admin/plugins.php | grep -o -E '<span class="plugin-name">([^<]*)</span>' | cut -d'>' -f2 | cut -d'<' -f1)

# # Get list of WordPress plugins
# echo "Checking WordPress plugins..."
# plugins=$(curl -s -L $url | grep -i -E -o "wp-content/plugins/[^/]+/" | cut -d'/' -f3 | sort -u)
# if [[ -n "$plugins" ]]; then
#     echo "WordPress plugins detected: $plugins"
#     for plugin in $plugins; do
#         latest_version=$(curl -s "https://api.wordpress.org/plugins/info/1.0/$plugin.json" | jq -r '.version')
#         installed_version=$(grep -i "Version" wp-content/plugins/$plugin/readme.txt | head -n1 | awk '{print $NF}')
#         if [[ "$latest_version" == "$installed_version" ]]; then
#             echo "$plugin is up to date."
#         else
#             echo "$plugin is out of date. Installed version is $installed_version, latest version is $latest_version."
#         fi
#     done
# else
#     echo "Unable to detect WordPress plugins."
# fi

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
   
# Get websites hosted on same IP address
echo "Checking other websites hosted on same IP address..."
websites_on_ip=$(whois -h whois.radb.net -- '-i origin '$ip_address'' | grep -Eo "([0-9.]+){4}/[0-9]+" | xargs -I % sh -c 'whois -h whois.radb.net -- "-i origin " $(echo % | cut -d"/" -f1) | grep "inetnum\|netname\|descr\|country" | awk '\''{print} END{print ""}'\''')
if [[ -n "$websites_on_ip" ]]; then
    echo "Other websites hosted on the same IP address:"
    echo "$websites_on_ip"
else
    echo "Unable to detect other websites hosted on the same IP address."
fi
