class Event < ApplicationRecord

  belongs_to :owner, class_name: 'User'

  has_many :event_attendees, foreign_key: :attendee_id
  has_many :attendees, through: :event_attendees

end
