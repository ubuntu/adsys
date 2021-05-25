- id: '{75545F76-DEC2-4ADA-B7B8-D5209FD48727}'
  name: GPO for Integration Test User
  rules:
      dconf:
        - key: org/gnome/desktop/background/picture-options
          value: none
          disabled: false
          meta: s
        - key: org/gnome/shell/old/old-data
          value: something
          disabled: false
          meta: s
        - key: org/gnome/desktop/background/picture-uri
          value: file:///usr/share/backgrounds/ubuntu.png
          disabled: false
          meta: s
        - key: org/gnome/shell/favorite-apps
          value: |4
               'firefox.desktop'
              'thunderbird.desktop'
              'org.gnome.Nautilus.desktop'
          disabled: false
          meta: as
- id: '{31B2F340-016D-11D2-945F-00C04FB984F9}'
  name: Default Domain Policy
  rules: {}
